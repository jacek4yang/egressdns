//! Microbenchmarks for the foreground data plane.
//!
//! Everything measured here runs on the request path, so a regression in any of these is a
//! regression in tail latency. Run with `cargo bench --bench hot_path`.

use std::hint::black_box;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use egressdns::cache::singleflight::{Join, SingleFlight};
use egressdns::cache::{
    AnswerSource, CacheEntry, CacheKey, DnsCache, DnssecMode, DnssecStatus, EntryKind, PolicyView,
};
use egressdns::config::{CacheConfig, ServeStaleConfig, TransportKind};
use egressdns::dns::message as msgutil;
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};

fn sample_response(count: usize) -> Message {
    let name = Name::from_utf8("www.example.com.").expect("name");
    let mut m = Message::new(0x1234, MessageType::Response, OpCode::Query);
    m.metadata.recursion_desired = true;
    m.metadata.recursion_available = true;
    m.add_query(Query::query(name.clone(), RecordType::A));
    for i in 0..count {
        m.add_answer(Record::from_rdata(
            name.clone(),
            300,
            RData::A(A(Ipv4Addr::new(
                104,
                16,
                (i / 254) as u8,
                ((i % 253) + 1) as u8,
            ))),
        ));
    }
    let mut edns = hickory_proto::op::Edns::new();
    edns.set_version(0);
    edns.set_max_payload(1232);
    m.set_edns(edns);
    m
}

fn key(name: &str) -> CacheKey {
    CacheKey::new(
        name,
        RecordType::A,
        DNSClass::IN,
        PolicyView::plain(Arc::from("default")),
        DnssecMode {
            dnssec_ok: false,
            checking_disabled: false,
        },
    )
}

fn entry(message: Message, now: tokio::time::Instant) -> Arc<CacheEntry> {
    Arc::new(CacheEntry {
        approx_bytes: egressdns::cache::estimate_bytes(&message),
        fingerprint: msgutil::answer_fingerprint(&message),
        message: Arc::new(message),
        received_at: now,
        received_unix: 1_700_000_000,
        ttl: 300,
        kind: EntryKind::Positive,
        dnssec: DnssecStatus::Insecure,
        source: AnswerSource {
            server: Arc::from("bench"),
            transport: TransportKind::Udp,
        },
        rrsig_expiry_unix: None,
    })
}

fn bench_parse(c: &mut Criterion) {
    let mut group = c.benchmark_group("message/parse");
    for count in [1usize, 4, 16] {
        let bytes = sample_response(count).to_vec().expect("encode");
        group.throughput(Throughput::Bytes(bytes.len() as u64));
        group.bench_function(format!("{count}_records"), |b| {
            b.iter(|| {
                let m = Message::from_vec(black_box(&bytes)).expect("decode");
                black_box(m.answers.len())
            })
        });
    }
    group.finish();
}

fn bench_serialize(c: &mut Criterion) {
    let mut group = c.benchmark_group("message/serialize");
    for count in [1usize, 4, 16] {
        let message = sample_response(count);
        group.bench_function(format!("{count}_records"), |b| {
            b.iter(|| {
                let out = msgutil::serialize_limited(black_box(&message), 1232).expect("encode");
                black_box(out.bytes.len())
            })
        });
    }
    group.finish();
}

fn bench_ttl(c: &mut Criterion) {
    let message = sample_response(8);
    c.bench_function("message/ttl_rewrite", |b| {
        b.iter_batched(
            || message.clone(),
            |mut m| {
                msgutil::age_ttls(&mut m, 17);
                msgutil::cap_ttls(&mut m, 60);
                black_box(msgutil::min_ttl(&m))
            },
            BatchSize::SmallInput,
        )
    });
}

fn bench_fingerprint(c: &mut Criterion) {
    let message = sample_response(8);
    c.bench_function("message/fingerprint", |b| {
        b.iter(|| black_box(msgutil::answer_fingerprint(black_box(&message))))
    });
}

fn bench_cache(c: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("runtime");
    let _guard = runtime.enter();
    let now = tokio::time::Instant::now();
    let cache = DnsCache::new(&CacheConfig::default(), &ServeStaleConfig::default());
    for i in 0..10_000u32 {
        cache.insert(
            key(&format!("n{i}.example.com.")),
            entry(sample_response(2), now),
        );
    }
    cache.run_maintenance();

    let hot = key("n5000.example.com.");
    c.bench_function("cache/hit", |b| {
        b.iter(|| black_box(cache.get(black_box(&hot), now).label()))
    });
    let cold = key("absent.example.com.");
    c.bench_function("cache/miss", |b| {
        b.iter(|| black_box(cache.get(black_box(&cold), now).label()))
    });
    c.bench_function("cache/key_construction", |b| {
        b.iter(|| black_box(key(black_box("www.example.com"))))
    });
}

fn bench_singleflight(c: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime");
    let _guard = runtime.enter();
    let sf: Arc<SingleFlight<CacheKey, u32>> = SingleFlight::new(64, 4_096);
    let k = key("flight.example.com.");
    c.bench_function("singleflight/uncontended", |b| {
        b.iter(|| match sf.join(black_box(k.clone())) {
            Join::Leader(leader) => {
                leader.complete(1);
                black_box(1u32)
            }
            Join::Follower(_) => black_box(2u32),
            Join::Saturated => black_box(3u32),
        })
    });
}

fn bench_acl(c: &mut Criterion) {
    use egressdns::dns::acl::Acl;
    let acl = Acl::new(
        vec![
            "10.0.0.0/8".parse().expect("net"),
            "172.16.0.0/12".parse().expect("net"),
            "192.168.0.0/16".parse().expect("net"),
            "fd00::/8".parse().expect("net"),
        ],
        vec!["10.9.9.0/24".parse().expect("net")],
    );
    let allowed: std::net::IpAddr = "10.1.2.3".parse().expect("ip");
    let denied: std::net::IpAddr = "203.0.113.9".parse().expect("ip");
    c.bench_function("acl/allow", |b| {
        b.iter(|| black_box(acl.permits(black_box(allowed))))
    });
    c.bench_function("acl/deny", |b| {
        b.iter(|| black_box(acl.permits(black_box(denied))))
    });
}

fn bench_ratelimit(c: &mut Criterion) {
    use egressdns::config::RateLimitConfig;
    use egressdns::dns::ratelimit::InboundLimiter;
    let limiter = InboundLimiter::new(&RateLimitConfig {
        enabled: true,
        per_client_qps: 1_000_000,
        per_client_burst: 1_000_000,
        global_qps: 1_000_000,
        global_burst: 1_000_000,
        client_table_size: 4_096,
    });
    let client: std::net::IpAddr = "10.1.2.3".parse().expect("ip");
    c.bench_function("ratelimit/check", |b| {
        b.iter(|| black_box(limiter.check(black_box(client))))
    });
}

fn bench_end_to_end_cache_hit(c: &mut Criterion) {
    // Approximates the whole cache-hit path: parse, key, lookup, age, cap, serialise.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("runtime");
    let _guard = runtime.enter();
    let now = tokio::time::Instant::now();
    let cache = DnsCache::new(&CacheConfig::default(), &ServeStaleConfig::default());
    let k = key("www.example.com.");
    cache.insert(k.clone(), entry(sample_response(2), now));
    cache.run_maintenance();

    let mut request = Message::new(1, MessageType::Query, OpCode::Query);
    request.add_query(Query::query(
        Name::from_utf8("www.example.com.").expect("name"),
        RecordType::A,
    ));
    let mut edns = hickory_proto::op::Edns::new();
    edns.set_max_payload(1232);
    request.set_edns(edns);
    let request_bytes = request.to_vec().expect("encode");

    c.bench_function("path/cache_hit_full", |b| {
        b.iter(|| {
            let parsed = Message::from_vec(black_box(&request_bytes)).expect("decode");
            let name = parsed.queries[0].name().to_string();
            let cache_key = key(&name);
            let lookup = cache.get(&cache_key, now);
            let mut response = match lookup {
                egressdns::cache::Lookup::Fresh { entry, .. } => (*entry.message).clone(),
                _ => unreachable!("the benchmark entry is always present"),
            };
            response.metadata.id = parsed.metadata.id;
            msgutil::age_ttls(&mut response, 5);
            msgutil::cap_ttls(&mut response, 60);
            let out = msgutil::serialize_limited(&response, 1232).expect("encode");
            black_box(out.bytes.len())
        })
    });
}

fn bench_estimate(c: &mut Criterion) {
    let message = sample_response(8);
    c.bench_function("cache/size_estimate", |b| {
        b.iter(|| black_box(egressdns::cache::estimate_bytes(black_box(&message))))
    });
}

fn config() -> Criterion {
    Criterion::default()
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(2))
        .sample_size(50)
}

criterion_group! {
    name = benches;
    config = config();
    targets =
        bench_parse,
        bench_serialize,
        bench_ttl,
        bench_fingerprint,
        bench_cache,
        bench_singleflight,
        bench_acl,
        bench_ratelimit,
        bench_estimate,
        bench_end_to_end_cache_hit,
}
criterion_main!(benches);
