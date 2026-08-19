//! Request coalescing.
//!
//! Concurrent identical cache misses must produce exactly one upstream operation. The
//! implementation is cancellation-safe: if the leader's future is dropped, for example
//! because the client went away or the foreground budget elapsed, waiters are woken with
//! [`FlightError::LeaderGone`] instead of hanging until their own timeout.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Arc;

use parking_lot::Mutex;
use tokio::sync::broadcast;

/// Why a follower did not receive a value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlightError {
    /// The leader was cancelled or panicked before publishing a result.
    LeaderGone,
    /// The leader published a failure.
    Failed(Arc<str>),
}

type Shared<V> = Result<V, FlightError>;

struct Shard<K, V> {
    map: HashMap<K, broadcast::Sender<Shared<V>>>,
}

/// A bounded, sharded singleflight registry.
pub struct SingleFlight<K, V> {
    shards: Vec<Mutex<Shard<K, V>>>,
    max_inflight_per_shard: usize,
}

/// Outcome of joining a flight.
pub enum Join<K, V>
where
    K: Eq + Hash + Clone + Send + 'static,
    V: Clone + Send + 'static,
{
    /// The caller is responsible for performing the work.
    Leader(Leader<K, V>),
    /// Another caller is already doing the work.
    Follower(Follower<V>),
    /// Too many distinct operations are already in flight.
    Saturated,
}

/// Leader handle. Dropping this without calling [`Leader::complete`] wakes followers with
/// [`FlightError::LeaderGone`].
pub struct Leader<K, V>
where
    K: Eq + Hash + Clone + Send + 'static,
    V: Clone + Send + 'static,
{
    key: Option<K>,
    tx: broadcast::Sender<Shared<V>>,
    owner: Arc<SingleFlight<K, V>>,
    published: bool,
}

/// Follower handle.
pub struct Follower<V: Clone> {
    rx: broadcast::Receiver<Shared<V>>,
}

impl<K, V> SingleFlight<K, V>
where
    K: Eq + Hash + Clone + Send + 'static,
    V: Clone + Send + 'static,
{
    /// Create a registry with `shards` shards and a per-shard in-flight ceiling.
    pub fn new(shards: usize, max_inflight_per_shard: usize) -> Arc<Self> {
        let shards = shards.max(1).next_power_of_two();
        Arc::new(Self {
            shards: (0..shards)
                .map(|_| {
                    Mutex::new(Shard {
                        map: HashMap::new(),
                    })
                })
                .collect(),
            max_inflight_per_shard: max_inflight_per_shard.max(1),
        })
    }

    fn shard_index(&self, key: &K) -> usize {
        use std::hash::{BuildHasher, RandomState};
        // A fixed hasher keeps shard assignment stable within a process run.
        static STATE: std::sync::OnceLock<RandomState> = std::sync::OnceLock::new();
        let state = STATE.get_or_init(RandomState::new);
        (state.hash_one(key) as usize) & (self.shards.len() - 1)
    }

    /// Join or start a flight for `key`.
    pub fn join(self: &Arc<Self>, key: K) -> Join<K, V> {
        let idx = self.shard_index(&key);
        let mut shard = self.shards[idx].lock();
        if let Some(tx) = shard.map.get(&key) {
            return Join::Follower(Follower { rx: tx.subscribe() });
        }
        if shard.map.len() >= self.max_inflight_per_shard {
            return Join::Saturated;
        }
        let (tx, _rx) = broadcast::channel(1);
        shard.map.insert(key.clone(), tx.clone());
        drop(shard);
        Join::Leader(Leader {
            key: Some(key),
            tx,
            owner: Arc::clone(self),
            published: false,
        })
    }

    fn remove(&self, key: &K) {
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].lock();
        shard.map.remove(key);
    }

    /// Number of flights currently in progress.
    pub fn inflight(&self) -> usize {
        self.shards.iter().map(|s| s.lock().map.len()).sum()
    }
}

impl<K, V> Leader<K, V>
where
    K: Eq + Hash + Clone + Send + 'static,
    V: Clone + Send + 'static,
{
    /// Publish a successful result to every waiter.
    pub fn complete(mut self, value: V) {
        self.publish(Ok(value));
    }

    /// Publish a failure to every waiter.
    pub fn fail(mut self, reason: &str) {
        self.publish(Err(FlightError::Failed(Arc::from(reason))));
    }

    fn publish(&mut self, value: Shared<V>) {
        if self.published {
            return;
        }
        self.published = true;
        if let Some(key) = self.key.take() {
            self.owner.remove(&key);
        }
        // A send error only means nobody is waiting, which is fine.
        let _ = self.tx.send(value);
    }
}

impl<K, V> Drop for Leader<K, V>
where
    K: Eq + Hash + Clone + Send + 'static,
    V: Clone + Send + 'static,
{
    fn drop(&mut self) {
        if !self.published {
            self.publish(Err(FlightError::LeaderGone));
        }
    }
}

impl<V: Clone> Follower<V> {
    /// Wait for the leader's result.
    pub async fn wait(mut self) -> Result<V, FlightError> {
        match self.rx.recv().await {
            Ok(Ok(v)) => Ok(v),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(FlightError::LeaderGone),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    #[tokio::test]
    async fn concurrent_misses_produce_one_operation() {
        let sf: Arc<SingleFlight<String, u32>> = SingleFlight::new(4, 128);
        let calls = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..32 {
            let sf = Arc::clone(&sf);
            let calls = Arc::clone(&calls);
            handles.push(tokio::spawn(async move {
                match sf.join("k".to_string()) {
                    Join::Leader(leader) => {
                        calls.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(30)).await;
                        leader.complete(7);
                        7u32
                    }
                    Join::Follower(f) => f.wait().await.expect("value"),
                    Join::Saturated => panic!("unexpected saturation"),
                }
            }));
        }
        for h in handles {
            assert_eq!(h.await.expect("join"), 7);
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(sf.inflight(), 0);
    }

    #[tokio::test]
    async fn cancelled_leader_wakes_followers() {
        let sf: Arc<SingleFlight<String, u32>> = SingleFlight::new(2, 128);
        let leader = match sf.join("k".to_string()) {
            Join::Leader(l) => l,
            _ => panic!("expected leader"),
        };
        let follower = match sf.join("k".to_string()) {
            Join::Follower(f) => f,
            _ => panic!("expected follower"),
        };
        drop(leader);
        assert_eq!(follower.wait().await, Err(FlightError::LeaderGone));
        assert_eq!(sf.inflight(), 0);
    }

    #[tokio::test]
    async fn failure_is_propagated() {
        let sf: Arc<SingleFlight<String, u32>> = SingleFlight::new(2, 128);
        let leader = match sf.join("k".to_string()) {
            Join::Leader(l) => l,
            _ => panic!("expected leader"),
        };
        let follower = match sf.join("k".to_string()) {
            Join::Follower(f) => f,
            _ => panic!("expected follower"),
        };
        leader.fail("upstream down");
        match follower.wait().await {
            Err(FlightError::Failed(msg)) => assert_eq!(&*msg, "upstream down"),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[tokio::test]
    async fn saturation_is_reported_not_unbounded() {
        let sf: Arc<SingleFlight<u64, u32>> = SingleFlight::new(1, 4);
        let mut leaders = Vec::new();
        for i in 0..4u64 {
            match sf.join(i) {
                Join::Leader(l) => leaders.push(l),
                other => panic!("expected leader for {i}, got {}", label(&other)),
            }
        }
        assert!(matches!(sf.join(99), Join::Saturated));
        drop(leaders);
        assert_eq!(sf.inflight(), 0);
    }

    fn label<K, V>(j: &Join<K, V>) -> &'static str
    where
        K: Eq + std::hash::Hash + Clone + Send + 'static,
        V: Clone + Send + 'static,
    {
        match j {
            Join::Leader(_) => "leader",
            Join::Follower(_) => "follower",
            Join::Saturated => "saturated",
        }
    }
}
