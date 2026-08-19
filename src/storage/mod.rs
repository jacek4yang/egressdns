//! Persistent state.
//!
//! SQLite holds only *derived* state: IP quality history, Cloudflare candidate history,
//! upstream statistics, aggregate hot-domain counts and network-generation metadata. Live
//! DNS answers are never persisted, because expiry, clock and DNSSEC semantics across a
//! restart are difficult to get right and the benefit is small.
//!
//! No DNS request ever waits for SQLite: writes go through a bounded channel to a
//! dedicated blocking worker, and reads happen only at startup and from the admin socket.

mod schema;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rusqlite::Connection;
use tokio::sync::mpsc;

pub use crate::config::StorageConfig;
use crate::error::StorageError;
use crate::ranking::model::PersistedQuality;

pub use schema::{CURRENT_SCHEMA_VERSION, MIGRATIONS};

/// A persisted IP quality row.
#[derive(Debug, Clone, PartialEq)]
pub struct QualityRow {
    /// Address as text.
    pub addr: String,
    /// Probe profile key.
    pub profile: String,
    /// Port.
    pub port: u16,
    /// Persisted model values.
    pub quality: PersistedQuality,
    /// Last update, seconds since the epoch.
    pub updated_unix: u64,
}

/// A persisted Cloudflare candidate row.
#[derive(Debug, Clone, PartialEq)]
pub struct CandidateRow {
    /// Address as text.
    pub addr: String,
    /// Origin label.
    pub origin: String,
    /// Highest validation stage reached.
    pub stage: String,
    /// Last seen, seconds since the epoch.
    pub last_seen_unix: u64,
    /// Network generation the evidence belongs to.
    pub generation: u64,
}

/// A persisted hot-domain row.
#[derive(Debug, Clone, PartialEq)]
pub struct HotRow {
    /// Query name.
    pub name: String,
    /// Query type as a numeric code.
    pub qtype: u16,
    /// Decayed popularity score.
    pub score: f64,
    /// Last seen, seconds since the epoch.
    pub last_seen_unix: u64,
}

/// A persisted upstream statistics row.
#[derive(Debug, Clone, PartialEq)]
pub struct UpstreamRow {
    /// Route identity as text.
    pub route: String,
    /// EWMA latency in milliseconds.
    pub ewma_ms: f64,
    /// Tail latency in milliseconds.
    pub p95_ms: f64,
    /// Success probability.
    pub success_probability: f64,
    /// Sample count.
    pub samples: u64,
    /// Last update, seconds since the epoch.
    pub updated_unix: u64,
}

/// A batch of writes.
#[derive(Debug)]
pub enum WriteBatch {
    /// IP quality rows.
    Quality(Vec<QualityRow>),
    /// Cloudflare candidate rows.
    Candidates(Vec<CandidateRow>),
    /// Hot-domain rows.
    Hot(Vec<HotRow>),
    /// Upstream statistics rows.
    Upstream(Vec<UpstreamRow>),
    /// Network generation metadata.
    Generation {
        /// Generation identifier.
        generation: u64,
        /// Fingerprint of the network state.
        fingerprint: u64,
        /// When it was published.
        published_unix: u64,
    },
    /// Prune expired rows.
    Prune {
        /// Rows older than this many seconds are removed.
        max_age_secs: u64,
        /// Row-count ceilings.
        limits: RowLimits,
    },
}

/// Row-count ceilings applied by pruning.
#[derive(Debug, Clone, Copy)]
pub struct RowLimits {
    /// Maximum quality rows.
    pub quality: usize,
    /// Maximum candidate rows.
    pub candidates: usize,
    /// Maximum hot-domain rows.
    pub hot: usize,
}

/// Handle to the persistence layer.
pub struct Storage {
    tx: Option<mpsc::Sender<WriteBatch>>,
    healthy: AtomicBool,
    dropped: AtomicU64,
    path: PathBuf,
    quarantined: parking_lot::Mutex<Option<PathBuf>>,
}

impl Storage {
    /// A disabled store. Every write is a no-op and the daemon runs on in-memory state.
    pub fn disabled() -> Arc<Self> {
        Arc::new(Self {
            tx: None,
            healthy: AtomicBool::new(false),
            dropped: AtomicU64::new(0),
            path: PathBuf::new(),
            quarantined: parking_lot::Mutex::new(None),
        })
    }

    /// Open the database, run migrations and start the write worker.
    ///
    /// A corrupt database is renamed aside and a fresh one is created; the daemon starts
    /// either way, because DNS service must never depend on the quality database.
    pub fn open(cfg: &StorageConfig) -> Arc<Self> {
        if !cfg.enabled {
            return Self::disabled();
        }
        match Self::try_open(cfg) {
            Ok(store) => store,
            Err(e) => {
                tracing::error!(
                    event = "storage.open_failed",
                    error = %e,
                    "continuing with in-memory quality state only"
                );
                Self::disabled()
            }
        }
    }

    fn try_open(cfg: &StorageConfig) -> Result<Arc<Self>, StorageError> {
        if let Some(parent) = cfg.path.parent() {
            std::fs::create_dir_all(parent).map_err(|source| StorageError::Io {
                path: parent.display().to_string(),
                source,
            })?;
        }
        let mut quarantined = None;
        let conn = match open_and_migrate(&cfg.path) {
            Ok(c) => c,
            Err(first) => {
                tracing::warn!(
                    event = "storage.corrupt",
                    error = %first,
                    "quarantining the damaged database and starting fresh"
                );
                let moved = quarantine(&cfg.path)?;
                quarantined = Some(moved);
                open_and_migrate(&cfg.path)?
            }
        };

        let (tx, rx) = mpsc::channel::<WriteBatch>(cfg.queue_size);
        let path = cfg.path.clone();
        std::thread::Builder::new()
            .name("egressdns-storage".into())
            .spawn(move || worker(conn, rx))
            .map_err(|source| StorageError::Io {
                path: path.display().to_string(),
                source,
            })?;

        Ok(Arc::new(Self {
            tx: Some(tx),
            healthy: AtomicBool::new(true),
            dropped: AtomicU64::new(0),
            path: cfg.path.clone(),
            quarantined: parking_lot::Mutex::new(quarantined),
        }))
    }

    /// Whether the store is usable.
    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Relaxed)
    }

    /// Path of the quarantined database, when one was moved aside.
    pub fn quarantined_path(&self) -> Option<PathBuf> {
        self.quarantined.lock().clone()
    }

    /// Number of write batches dropped because the queue was full.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Database path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Enqueue a batch. Never blocks; a full queue drops the batch and increments a
    /// counter, because losing derived statistics is always preferable to stalling DNS.
    pub fn enqueue(&self, batch: WriteBatch) {
        let Some(tx) = &self.tx else {
            return;
        };
        if tx.try_send(batch).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            metrics::counter!(
                crate::metrics::names::STORAGE_OPS_TOTAL,
                "operation" => "enqueue",
                "outcome" => "dropped",
            )
            .increment(1);
        }
    }

    /// Wait until every queued write has been applied, up to a short deadline.
    ///
    /// Used at shutdown so learned state gathered in the final seconds is not lost. It is
    /// bounded and best-effort by design: a slow or full disk must delay process exit by
    /// seconds at most, never indefinitely, because the data is an optimisation and the
    /// process is already stopping.
    pub async fn flush(&self) {
        let Some(tx) = &self.tx else {
            return;
        };
        // Blocking the calling thread here would stall every other task on that runtime
        // worker, including the ones still trying to drain the queue we are waiting on.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(3);
        while tx.max_capacity() != tx.capacity() && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    }

    /// Approximate queue depth.
    pub fn queue_depth(&self) -> usize {
        self.tx
            .as_ref()
            .map(|t| t.max_capacity() - t.capacity())
            .unwrap_or(0)
    }

    /// Load persisted quality rows. Blocking; called once at startup.
    pub fn load_quality(&self, limit: usize) -> Vec<QualityRow> {
        self.with_reader(|conn| schema::load_quality(conn, limit))
            .unwrap_or_default()
    }

    /// Load persisted candidate rows. Blocking; called once at startup.
    pub fn load_candidates(&self, limit: usize) -> Vec<CandidateRow> {
        self.with_reader(|conn| schema::load_candidates(conn, limit))
            .unwrap_or_default()
    }

    /// Load persisted hot-domain rows. Blocking; called once at startup.
    pub fn load_hot(&self, limit: usize) -> Vec<HotRow> {
        self.with_reader(|conn| schema::load_hot(conn, limit))
            .unwrap_or_default()
    }

    /// Recorded schema version, for diagnostics.
    pub fn schema_version(&self) -> Option<i64> {
        self.with_reader(schema::schema_version).ok()
    }

    /// Load persisted upstream statistics rows.
    pub fn load_upstream(&self) -> Vec<UpstreamRow> {
        self.with_reader(schema::load_upstream).unwrap_or_default()
    }

    /// Load the last recorded network generation.
    pub fn load_generation(&self) -> Option<(u64, u64)> {
        self.with_reader(schema::load_generation).ok().flatten()
    }

    fn with_reader<T>(
        &self,
        f: impl FnOnce(&Connection) -> Result<T, rusqlite::Error>,
    ) -> Result<T, StorageError> {
        if self.tx.is_none() {
            return Err(StorageError::WorkerStopped);
        }
        let conn = Connection::open(&self.path)?;
        configure(&conn)?;
        Ok(f(&conn)?)
    }
}

fn worker(conn: Connection, mut rx: mpsc::Receiver<WriteBatch>) {
    while let Some(batch) = rx.blocking_recv() {
        let label = match &batch {
            WriteBatch::Quality(_) => "quality",
            WriteBatch::Candidates(_) => "candidates",
            WriteBatch::Hot(_) => "hot",
            WriteBatch::Upstream(_) => "upstream",
            WriteBatch::Generation { .. } => "generation",
            WriteBatch::Prune { .. } => "prune",
        };
        let result = schema::apply(&conn, batch);
        let outcome = if result.is_ok() { "ok" } else { "error" };
        if let Err(e) = result {
            tracing::warn!(event = "storage.write_failed", operation = label, error = %e);
        }
        metrics::counter!(
            crate::metrics::names::STORAGE_OPS_TOTAL,
            "operation" => label,
            "outcome" => outcome,
        )
        .increment(1);
    }
}

fn open_and_migrate(path: &Path) -> Result<Connection, StorageError> {
    let conn = Connection::open(path)?;
    configure(&conn)?;
    // A quick integrity check catches most corruption before it can confuse migrations.
    let ok: String = conn.query_row("PRAGMA quick_check(1)", [], |row| row.get(0))?;
    if ok != "ok" {
        return Err(StorageError::Quarantined {
            reason: crate::util::bounded(&ok, 120),
        });
    }
    schema::migrate(&conn)?;
    Ok(conn)
}

fn configure(conn: &Connection) -> Result<(), rusqlite::Error> {
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.busy_timeout(Duration::from_secs(5))?;
    Ok(())
}

fn quarantine(path: &Path) -> Result<PathBuf, StorageError> {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let target = path.with_extension(format!("corrupt-{stamp}"));
    std::fs::rename(path, &target).map_err(|source| StorageError::Io {
        path: path.display().to_string(),
        source,
    })?;
    // WAL and shm files belong to the quarantined database.
    for suffix in ["-wal", "-shm"] {
        let mut side = path.as_os_str().to_os_string();
        side.push(suffix);
        let side = PathBuf::from(side);
        if side.exists() {
            let mut moved = target.as_os_str().to_os_string();
            moved.push(suffix);
            let _ = std::fs::rename(&side, PathBuf::from(moved));
        }
    }
    Ok(target)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(dir: &tempfile::TempDir) -> StorageConfig {
        StorageConfig {
            enabled: true,
            path: dir.path().join("state.sqlite3"),
            queue_size: 16,
            ..StorageConfig::default()
        }
    }

    fn quality_row(addr: &str) -> QualityRow {
        QualityRow {
            addr: addr.to_string(),
            profile: "https".into(),
            port: 443,
            quality: PersistedQuality {
                alpha: 5.0,
                beta: 1.0,
                ewma_ms: 12.5,
                p95_ms: 30.0,
                jitter_ms: 2.0,
                samples: 6,
                successes: 5,
                generation: 3,
            },
            updated_unix: 1_700_000_000,
        }
    }

    #[tokio::test]
    async fn round_trip_quality_rows() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Storage::open(&cfg(&dir));
        assert!(store.is_healthy());
        store.enqueue(WriteBatch::Quality(vec![
            quality_row("104.16.0.1"),
            quality_row("104.16.0.2"),
        ]));
        // Give the worker a moment to drain.
        tokio::time::sleep(Duration::from_millis(200)).await;
        let rows = store.load_quality(100);
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().any(|r| r.addr == "104.16.0.1"));
        assert_eq!(rows[0].quality.generation, 3);
    }

    #[tokio::test]
    async fn corrupt_database_is_quarantined_and_service_continues() {
        let dir = tempfile::tempdir().expect("tempdir");
        let c = cfg(&dir);
        std::fs::write(&c.path, b"this is definitely not a sqlite database").expect("write");
        let store = Storage::open(&c);
        assert!(store.is_healthy(), "the daemon must still start");
        assert!(
            store.quarantined_path().is_some(),
            "the damaged file must be moved aside"
        );
        store.enqueue(WriteBatch::Quality(vec![quality_row("104.16.0.1")]));
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(store.load_quality(10).len(), 1);
    }

    #[tokio::test]
    async fn disabled_storage_is_a_no_op() {
        let store = Storage::disabled();
        assert!(!store.is_healthy());
        store.enqueue(WriteBatch::Quality(vec![quality_row("104.16.0.1")]));
        assert!(store.load_quality(10).is_empty());
        assert_eq!(store.queue_depth(), 0);
    }

    #[tokio::test]
    async fn full_queue_drops_instead_of_blocking() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut c = cfg(&dir);
        c.queue_size = 1;
        let store = Storage::open(&c);
        for _ in 0..500 {
            store.enqueue(WriteBatch::Quality(vec![quality_row("104.16.0.1")]));
        }
        // The point is that the loop above completed without blocking.
        assert!(store.dropped() > 0, "expected some batches to be dropped");
    }

    #[tokio::test]
    async fn pruning_bounds_the_tables() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Storage::open(&cfg(&dir));
        let rows: Vec<QualityRow> = (0..50)
            .map(|i| quality_row(&format!("104.16.0.{i}")))
            .collect();
        store.enqueue(WriteBatch::Quality(rows));
        store.enqueue(WriteBatch::Prune {
            max_age_secs: u64::MAX,
            limits: RowLimits {
                quality: 10,
                candidates: 10,
                hot: 10,
            },
        });
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(store.load_quality(1_000).len() <= 10);
    }

    #[tokio::test]
    async fn generation_round_trip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Storage::open(&cfg(&dir));
        store.enqueue(WriteBatch::Generation {
            generation: 42,
            fingerprint: 0xdead_beef,
            published_unix: 1_700_000_000,
        });
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(store.load_generation(), Some((42, 0xdead_beef)));
    }
}
