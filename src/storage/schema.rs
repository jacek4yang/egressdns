//! SQLite schema, migrations and statements.

use rusqlite::{params, Connection, OptionalExtension};

use crate::error::StorageError;
use crate::ranking::model::PersistedQuality;

use super::{CandidateRow, HotRow, QualityRow, RowLimits, UpstreamRow, WriteBatch};

/// Highest schema version this build understands.
pub const CURRENT_SCHEMA_VERSION: i64 = 1;

/// Ordered migrations. Index `n` migrates from version `n` to version `n + 1`.
pub const MIGRATIONS: &[&str] = &[
    // 0 -> 1
    r#"
    CREATE TABLE IF NOT EXISTS ip_quality (
        addr        TEXT NOT NULL,
        profile     TEXT NOT NULL,
        port        INTEGER NOT NULL,
        alpha       REAL NOT NULL,
        beta        REAL NOT NULL,
        ewma_ms     REAL NOT NULL,
        p95_ms      REAL NOT NULL,
        jitter_ms   REAL NOT NULL,
        samples     INTEGER NOT NULL,
        successes   INTEGER NOT NULL,
        generation  INTEGER NOT NULL,
        updated     INTEGER NOT NULL,
        PRIMARY KEY (addr, profile, port)
    );
    CREATE INDEX IF NOT EXISTS ip_quality_updated ON ip_quality(updated);

    CREATE TABLE IF NOT EXISTS cf_candidates (
        addr        TEXT PRIMARY KEY,
        origin      TEXT NOT NULL,
        stage       TEXT NOT NULL,
        last_seen   INTEGER NOT NULL,
        generation  INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS cf_candidates_last_seen ON cf_candidates(last_seen);

    CREATE TABLE IF NOT EXISTS hot_domains (
        name        TEXT NOT NULL,
        qtype       INTEGER NOT NULL,
        score       REAL NOT NULL,
        last_seen   INTEGER NOT NULL,
        PRIMARY KEY (name, qtype)
    );
    CREATE INDEX IF NOT EXISTS hot_domains_score ON hot_domains(score);

    CREATE TABLE IF NOT EXISTS upstream_stats (
        route               TEXT PRIMARY KEY,
        ewma_ms             REAL NOT NULL,
        p95_ms              REAL NOT NULL,
        success_probability REAL NOT NULL,
        samples             INTEGER NOT NULL,
        updated             INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS network_generation (
        id          INTEGER PRIMARY KEY CHECK (id = 1),
        generation  INTEGER NOT NULL,
        fingerprint INTEGER NOT NULL,
        published   INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS dataset_meta (
        name        TEXT PRIMARY KEY,
        etag        TEXT,
        fetched     INTEGER NOT NULL,
        records     INTEGER NOT NULL
    );
    "#,
];

/// Apply pending migrations.
pub fn migrate(conn: &Connection) -> Result<(), StorageError> {
    conn.execute_batch("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);")?;
    let current: i64 = conn
        .query_row("SELECT version FROM schema_version LIMIT 1", [], |r| {
            r.get(0)
        })
        .optional()?
        .unwrap_or(0);
    if current > CURRENT_SCHEMA_VERSION {
        return Err(StorageError::SchemaTooNew {
            found: current,
            supported: CURRENT_SCHEMA_VERSION,
        });
    }
    for (index, sql) in MIGRATIONS.iter().enumerate() {
        let from = index as i64;
        if from < current {
            continue;
        }
        conn.execute_batch(sql)?;
    }
    conn.execute("DELETE FROM schema_version", [])?;
    conn.execute(
        "INSERT INTO schema_version (version) VALUES (?1)",
        params![CURRENT_SCHEMA_VERSION],
    )?;
    Ok(())
}

/// Current schema version recorded in the database.
pub fn schema_version(conn: &Connection) -> Result<i64, rusqlite::Error> {
    conn.query_row("SELECT version FROM schema_version LIMIT 1", [], |r| {
        r.get(0)
    })
    .optional()
    .map(|v| v.unwrap_or(0))
}

/// Apply one write batch.
pub fn apply(conn: &Connection, batch: WriteBatch) -> Result<(), rusqlite::Error> {
    match batch {
        WriteBatch::Quality(rows) => {
            let tx = conn.unchecked_transaction()?;
            {
                let mut stmt = tx.prepare_cached(
                    "INSERT INTO ip_quality
                        (addr, profile, port, alpha, beta, ewma_ms, p95_ms, jitter_ms,
                         samples, successes, generation, updated)
                     VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)
                     ON CONFLICT(addr, profile, port) DO UPDATE SET
                        alpha=excluded.alpha, beta=excluded.beta, ewma_ms=excluded.ewma_ms,
                        p95_ms=excluded.p95_ms, jitter_ms=excluded.jitter_ms,
                        samples=excluded.samples, successes=excluded.successes,
                        generation=excluded.generation, updated=excluded.updated",
                )?;
                for r in rows {
                    stmt.execute(params![
                        r.addr,
                        r.profile,
                        r.port,
                        r.quality.alpha,
                        r.quality.beta,
                        r.quality.ewma_ms,
                        r.quality.p95_ms,
                        r.quality.jitter_ms,
                        r.quality.samples,
                        r.quality.successes,
                        r.quality.generation as i64,
                        r.updated_unix as i64,
                    ])?;
                }
            }
            tx.commit()
        }
        WriteBatch::Candidates(rows) => {
            let tx = conn.unchecked_transaction()?;
            {
                let mut stmt = tx.prepare_cached(
                    "INSERT INTO cf_candidates (addr, origin, stage, last_seen, generation)
                     VALUES (?1,?2,?3,?4,?5)
                     ON CONFLICT(addr) DO UPDATE SET
                        origin=excluded.origin, stage=excluded.stage,
                        last_seen=excluded.last_seen, generation=excluded.generation",
                )?;
                for r in rows {
                    stmt.execute(params![
                        r.addr,
                        r.origin,
                        r.stage,
                        r.last_seen_unix as i64,
                        r.generation as i64
                    ])?;
                }
            }
            tx.commit()
        }
        WriteBatch::Hot(rows) => {
            let tx = conn.unchecked_transaction()?;
            {
                let mut stmt = tx.prepare_cached(
                    "INSERT INTO hot_domains (name, qtype, score, last_seen)
                     VALUES (?1,?2,?3,?4)
                     ON CONFLICT(name, qtype) DO UPDATE SET
                        score=excluded.score, last_seen=excluded.last_seen",
                )?;
                for r in rows {
                    stmt.execute(params![r.name, r.qtype, r.score, r.last_seen_unix as i64])?;
                }
            }
            tx.commit()
        }
        WriteBatch::Upstream(rows) => {
            let tx = conn.unchecked_transaction()?;
            {
                let mut stmt = tx.prepare_cached(
                    "INSERT INTO upstream_stats
                        (route, ewma_ms, p95_ms, success_probability, samples, updated)
                     VALUES (?1,?2,?3,?4,?5,?6)
                     ON CONFLICT(route) DO UPDATE SET
                        ewma_ms=excluded.ewma_ms, p95_ms=excluded.p95_ms,
                        success_probability=excluded.success_probability,
                        samples=excluded.samples, updated=excluded.updated",
                )?;
                for r in rows {
                    stmt.execute(params![
                        r.route,
                        r.ewma_ms,
                        r.p95_ms,
                        r.success_probability,
                        r.samples as i64,
                        r.updated_unix as i64
                    ])?;
                }
            }
            tx.commit()
        }
        WriteBatch::Generation {
            generation,
            fingerprint,
            published_unix,
        } => {
            conn.execute(
                "INSERT INTO network_generation (id, generation, fingerprint, published)
                 VALUES (1, ?1, ?2, ?3)
                 ON CONFLICT(id) DO UPDATE SET
                    generation=excluded.generation, fingerprint=excluded.fingerprint,
                    published=excluded.published",
                params![generation as i64, fingerprint as i64, published_unix as i64],
            )?;
            Ok(())
        }
        WriteBatch::Prune {
            max_age_secs,
            limits,
        } => prune(conn, max_age_secs, limits),
    }
}

fn prune(conn: &Connection, max_age_secs: u64, limits: RowLimits) -> Result<(), rusqlite::Error> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0) as i64;
    let cutoff = now.saturating_sub(max_age_secs.min(i64::MAX as u64) as i64);
    conn.execute("DELETE FROM ip_quality WHERE updated < ?1", params![cutoff])?;
    conn.execute(
        "DELETE FROM cf_candidates WHERE last_seen < ?1",
        params![cutoff],
    )?;
    conn.execute(
        "DELETE FROM hot_domains WHERE last_seen < ?1",
        params![cutoff],
    )?;
    conn.execute(
        "DELETE FROM ip_quality WHERE rowid NOT IN
            (SELECT rowid FROM ip_quality ORDER BY updated DESC LIMIT ?1)",
        params![limits.quality as i64],
    )?;
    conn.execute(
        "DELETE FROM cf_candidates WHERE rowid NOT IN
            (SELECT rowid FROM cf_candidates ORDER BY last_seen DESC LIMIT ?1)",
        params![limits.candidates as i64],
    )?;
    conn.execute(
        "DELETE FROM hot_domains WHERE rowid NOT IN
            (SELECT rowid FROM hot_domains ORDER BY score DESC LIMIT ?1)",
        params![limits.hot as i64],
    )?;
    Ok(())
}

/// Load quality rows, most recently updated first.
pub fn load_quality(conn: &Connection, limit: usize) -> Result<Vec<QualityRow>, rusqlite::Error> {
    let mut stmt = conn.prepare(
        "SELECT addr, profile, port, alpha, beta, ewma_ms, p95_ms, jitter_ms,
                samples, successes, generation, updated
         FROM ip_quality ORDER BY updated DESC LIMIT ?1",
    )?;
    let rows = stmt.query_map(params![limit as i64], |row| {
        Ok(QualityRow {
            addr: row.get(0)?,
            profile: row.get(1)?,
            port: row.get(2)?,
            quality: PersistedQuality {
                alpha: row.get(3)?,
                beta: row.get(4)?,
                ewma_ms: row.get(5)?,
                p95_ms: row.get(6)?,
                jitter_ms: row.get(7)?,
                samples: row.get(8)?,
                successes: row.get(9)?,
                generation: row.get::<_, i64>(10)? as u64,
            },
            updated_unix: row.get::<_, i64>(11)? as u64,
        })
    })?;
    rows.collect()
}

/// Load candidate rows, most recently seen first.
pub fn load_candidates(
    conn: &Connection,
    limit: usize,
) -> Result<Vec<CandidateRow>, rusqlite::Error> {
    let mut stmt = conn.prepare(
        "SELECT addr, origin, stage, last_seen, generation
         FROM cf_candidates ORDER BY last_seen DESC LIMIT ?1",
    )?;
    let rows = stmt.query_map(params![limit as i64], |row| {
        Ok(CandidateRow {
            addr: row.get(0)?,
            origin: row.get(1)?,
            stage: row.get(2)?,
            last_seen_unix: row.get::<_, i64>(3)? as u64,
            generation: row.get::<_, i64>(4)? as u64,
        })
    })?;
    rows.collect()
}

/// Load hot-domain rows, most popular first.
pub fn load_hot(conn: &Connection, limit: usize) -> Result<Vec<HotRow>, rusqlite::Error> {
    let mut stmt = conn.prepare(
        "SELECT name, qtype, score, last_seen FROM hot_domains ORDER BY score DESC LIMIT ?1",
    )?;
    let rows = stmt.query_map(params![limit as i64], |row| {
        Ok(HotRow {
            name: row.get(0)?,
            qtype: row.get(1)?,
            score: row.get(2)?,
            last_seen_unix: row.get::<_, i64>(3)? as u64,
        })
    })?;
    rows.collect()
}

/// Load upstream statistics rows.
pub fn load_upstream(conn: &Connection) -> Result<Vec<UpstreamRow>, rusqlite::Error> {
    let mut stmt = conn.prepare(
        "SELECT route, ewma_ms, p95_ms, success_probability, samples, updated
         FROM upstream_stats",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(UpstreamRow {
            route: row.get(0)?,
            ewma_ms: row.get(1)?,
            p95_ms: row.get(2)?,
            success_probability: row.get(3)?,
            samples: row.get::<_, i64>(4)? as u64,
            updated_unix: row.get::<_, i64>(5)? as u64,
        })
    })?;
    rows.collect()
}

/// Load the recorded network generation and fingerprint.
pub fn load_generation(conn: &Connection) -> Result<Option<(u64, u64)>, rusqlite::Error> {
    conn.query_row(
        "SELECT generation, fingerprint FROM network_generation WHERE id = 1",
        [],
        |row| Ok((row.get::<_, i64>(0)? as u64, row.get::<_, i64>(1)? as u64)),
    )
    .optional()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn() -> Connection {
        let c = Connection::open_in_memory().expect("memory db");
        migrate(&c).expect("migrate");
        c
    }

    #[test]
    fn migration_is_idempotent() {
        let c = conn();
        assert_eq!(schema_version(&c).expect("version"), CURRENT_SCHEMA_VERSION);
        migrate(&c).expect("second migrate");
        migrate(&c).expect("third migrate");
        assert_eq!(schema_version(&c).expect("version"), CURRENT_SCHEMA_VERSION);
    }

    #[test]
    fn a_newer_schema_is_refused() {
        let c = Connection::open_in_memory().expect("memory db");
        c.execute_batch("CREATE TABLE schema_version (version INTEGER NOT NULL);")
            .expect("create");
        c.execute("INSERT INTO schema_version VALUES (999)", [])
            .expect("insert");
        assert!(matches!(
            migrate(&c),
            Err(StorageError::SchemaTooNew { found: 999, .. })
        ));
    }

    #[test]
    fn every_table_exists_after_migration() {
        let c = conn();
        for table in [
            "ip_quality",
            "cf_candidates",
            "hot_domains",
            "upstream_stats",
            "network_generation",
            "dataset_meta",
            "schema_version",
        ] {
            let count: i64 = c
                .query_row(
                    "SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?1",
                    params![table],
                    |r| r.get(0),
                )
                .expect("query");
            assert_eq!(count, 1, "table {table} missing");
        }
    }

    #[test]
    fn upsert_replaces_rather_than_duplicating() {
        let c = conn();
        let row = QualityRow {
            addr: "104.16.0.1".into(),
            profile: "https".into(),
            port: 443,
            quality: PersistedQuality {
                alpha: 2.0,
                beta: 1.0,
                ewma_ms: 10.0,
                p95_ms: 20.0,
                jitter_ms: 1.0,
                samples: 2,
                successes: 1,
                generation: 1,
            },
            updated_unix: 100,
        };
        apply(&c, WriteBatch::Quality(vec![row.clone()])).expect("write");
        let mut updated = row.clone();
        updated.quality.alpha = 9.0;
        updated.updated_unix = 200;
        apply(&c, WriteBatch::Quality(vec![updated])).expect("write");
        let rows = load_quality(&c, 10).expect("load");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].quality.alpha, 9.0);
    }

    #[test]
    fn prune_enforces_row_limits() {
        let c = conn();
        let rows: Vec<QualityRow> = (0..100)
            .map(|i| QualityRow {
                addr: format!("104.16.0.{i}"),
                profile: "https".into(),
                port: 443,
                quality: PersistedQuality {
                    alpha: 1.0,
                    beta: 1.0,
                    ewma_ms: 1.0,
                    p95_ms: 1.0,
                    jitter_ms: 0.0,
                    samples: 1,
                    successes: 1,
                    generation: 1,
                },
                updated_unix: 1_000 + i as u64,
            })
            .collect();
        apply(&c, WriteBatch::Quality(rows)).expect("write");
        apply(
            &c,
            WriteBatch::Prune {
                max_age_secs: u64::MAX,
                limits: RowLimits {
                    quality: 5,
                    candidates: 5,
                    hot: 5,
                },
            },
        )
        .expect("prune");
        assert_eq!(load_quality(&c, 1_000).expect("load").len(), 5);
    }

    #[test]
    fn hot_and_candidate_round_trip() {
        let c = conn();
        apply(
            &c,
            WriteBatch::Hot(vec![HotRow {
                name: "example.com.".into(),
                qtype: 1,
                score: 12.5,
                last_seen_unix: 5,
            }]),
        )
        .expect("write");
        apply(
            &c,
            WriteBatch::Candidates(vec![CandidateRow {
                addr: "104.16.0.1".into(),
                origin: "seed".into(),
                stage: "http_ok".into(),
                last_seen_unix: 7,
                generation: 2,
            }]),
        )
        .expect("write");
        assert_eq!(load_hot(&c, 10).expect("load")[0].score, 12.5);
        assert_eq!(load_candidates(&c, 10).expect("load")[0].generation, 2);
    }

    #[test]
    fn upstream_stats_round_trip() {
        let c = conn();
        apply(
            &c,
            WriteBatch::Upstream(vec![UpstreamRow {
                route: "cloudflare-dot/dot/1.1.1.1".into(),
                ewma_ms: 8.0,
                p95_ms: 20.0,
                success_probability: 0.99,
                samples: 1_000,
                updated_unix: 9,
            }]),
        )
        .expect("write");
        let rows = load_upstream(&c).expect("load");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].samples, 1_000);
    }
}
