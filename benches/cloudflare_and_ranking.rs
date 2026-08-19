//! Microbenchmarks for the optimization subsystems.
//!
//! These do not run on the request path except for prefix membership and address ordering,
//! which are measured first.

use std::collections::HashMap;
use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use egressdns::cloudflare::prefixes::PrefixSnapshot;
use egressdns::cloudflare::seeds;
use egressdns::config::{RankingConfig, SamplingConfig};
use egressdns::ranking::{order_addresses, ObservationClass, QualityStats};

fn bench_prefix_membership(c: &mut Criterion) {
    let snapshot = PrefixSnapshot::builtin();
    let inside: IpAddr = "104.16.55.9".parse().expect("ip");
    let outside: IpAddr = "8.8.8.8".parse().expect("ip");
    let v6: IpAddr = "2606:4700::1111".parse().expect("ip");
    c.bench_function("cloudflare/prefix_hit_v4", |b| {
        b.iter(|| black_box(snapshot.contains(black_box(inside))))
    });
    c.bench_function("cloudflare/prefix_miss_v4", |b| {
        b.iter(|| black_box(snapshot.contains(black_box(outside))))
    });
    c.bench_function("cloudflare/prefix_hit_v6", |b| {
        b.iter(|| black_box(snapshot.contains(black_box(v6))))
    });
}

fn bench_ranking(c: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("runtime");
    let _guard = runtime.enter();
    let now = tokio::time::Instant::now();
    let cfg = RankingConfig::default();

    let mut group = c.benchmark_group("ranking/order");
    for count in [2usize, 4, 8, 16] {
        let addrs: Vec<IpAddr> = (0..count)
            .map(|i| IpAddr::V4(Ipv4Addr::new(104, 16, 0, (i + 1) as u8)))
            .collect();
        let mut quality = HashMap::new();
        for (i, addr) in addrs.iter().enumerate() {
            let mut s = QualityStats::new(1);
            for _ in 0..16 {
                s.record(
                    ObservationClass::Success,
                    Some(Duration::from_millis(5 + (i as u64 * 13) % 200)),
                    now,
                    &cfg,
                );
            }
            quality.insert(*addr, s);
        }
        group.throughput(Throughput::Elements(count as u64));
        group.bench_function(format!("{count}_addresses"), |b| {
            b.iter(|| {
                black_box(order_addresses(
                    black_box(&addrs),
                    black_box(&quality),
                    &cfg,
                    now,
                    42,
                ))
            })
        });
    }
    group.finish();
}

fn bench_quality_model(c: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("runtime");
    let _guard = runtime.enter();
    let now = tokio::time::Instant::now();
    let cfg = RankingConfig::default();
    let mut stats = QualityStats::new(1);
    for _ in 0..32 {
        stats.record(
            ObservationClass::Success,
            Some(Duration::from_millis(12)),
            now,
            &cfg,
        );
    }
    c.bench_function("ranking/expected_cost", |b| {
        b.iter(|| black_box(stats.expected_cost(&cfg, now)))
    });
    c.bench_function("ranking/record_observation", |b| {
        b.iter(|| {
            let mut s = stats.clone();
            s.record(
                ObservationClass::Success,
                Some(Duration::from_millis(9)),
                now,
                &cfg,
            );
            black_box(s.success_probability())
        })
    });
}

fn bench_seed_parsing(c: &mut Criterion) {
    let fixture = include_bytes!("../tests/fixtures/seed_cmcc.txt");
    let mut big = String::new();
    for i in 0..1_000 {
        big.push_str(&format!("104.16.{}.{}#comment\n", i / 254, (i % 253) + 1));
    }
    c.bench_function("cloudflare/seed_parse_small", |b| {
        b.iter(|| {
            black_box(
                seeds::parse(black_box(fixture), 256)
                    .expect("parses")
                    .0
                    .len(),
            )
        })
    });
    c.bench_function("cloudflare/seed_parse_1000", |b| {
        b.iter(|| {
            black_box(
                seeds::parse(black_box(big.as_bytes()), 4_096)
                    .expect("parses")
                    .0
                    .len(),
            )
        })
    });
}

fn bench_prefix_parse(c: &mut Criterion) {
    let fixture = include_bytes!("../tests/fixtures/cloudflare_ips_api.json");
    c.bench_function("cloudflare/prefix_json_parse", |b| {
        b.iter(|| {
            black_box(
                egressdns::cloudflare::prefixes::parse_api_json(black_box(fixture), 0)
                    .expect("parses")
                    .len(),
            )
        })
    });
}

fn bench_sampler(c: &mut Criterion) {
    let snapshot = PrefixSnapshot::builtin();
    let sampler =
        egressdns::cloudflare::sampler::StratifiedSampler::new(&SamplingConfig::default());
    c.bench_function("cloudflare/sample_round_32", |b| {
        b.iter(|| black_box(sampler.next_round(black_box(&snapshot), 32).len()))
    });
}

fn bench_storage_batch(c: &mut Criterion) {
    use egressdns::ranking::model::PersistedQuality;
    use egressdns::storage::{QualityRow, Storage, StorageConfig, WriteBatch};

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .expect("runtime");
    let _guard = runtime.enter();
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = Storage::open(&StorageConfig {
        enabled: true,
        path: dir.path().join("bench.sqlite3"),
        queue_size: 1_024,
        ..StorageConfig::default()
    });

    let rows: Vec<QualityRow> = (0..500)
        .map(|i| QualityRow {
            addr: format!("104.16.{}.{}", i / 254, (i % 253) + 1),
            profile: "https:example.com".into(),
            port: 443,
            quality: PersistedQuality {
                alpha: 12.0,
                beta: 1.0,
                ewma_ms: 11.0,
                p95_ms: 30.0,
                jitter_ms: 2.0,
                samples: 13,
                successes: 12,
                generation: 1,
            },
            updated_unix: 1_700_000_000,
        })
        .collect();

    c.bench_function("storage/enqueue_500_rows", |b| {
        b.iter(|| {
            storage.enqueue(WriteBatch::Quality(black_box(rows.clone())));
        })
    });
}

fn bench_ipclass(c: &mut Criterion) {
    let global: IpAddr = "104.16.0.1".parse().expect("ip");
    let private: IpAddr = "10.0.0.1".parse().expect("ip");
    c.bench_function("util/ipclass_global", |b| {
        b.iter(|| black_box(egressdns::util::ipclass::classify(black_box(global))))
    });
    c.bench_function("util/ipclass_private", |b| {
        b.iter(|| black_box(egressdns::util::ipclass::classify(black_box(private))))
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
        bench_prefix_membership,
        bench_ranking,
        bench_quality_model,
        bench_seed_parsing,
        bench_prefix_parse,
        bench_sampler,
        bench_ipclass,
        bench_storage_batch,
}
criterion_main!(benches);
