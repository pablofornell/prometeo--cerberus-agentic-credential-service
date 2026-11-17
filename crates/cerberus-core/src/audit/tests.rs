//! Audit tests. Tampering goes straight to the SQLite file, around the store and its triggers.

use std::path::PathBuf;
use std::sync::Arc;

use cerberus_crypto::{KeyTree, SecretString, Vmk};
use cerberus_store::{AuditPendingRow, AuditRow, Blobs, OpenOptions, Store};
use cerberus_types::{AgentId, ManualClock, RequestId, VaultId, t0};
use jiff::SignedDuration;
use sqlx::Connection;
use sqlx::sqlite::{SqliteConnectOptions, SqliteConnection};
use tempfile::TempDir;

use super::chain::{entry_hash, make_head, row_hmac};
use super::*;

struct Fixture {
    _dir: TempDir,
    path: PathBuf,
    store: Store,
    keys: Arc<KeyTree>,
    vault: VaultId,
    clock: ManualClock,
    writer: Arc<AuditWriter>,
}

async fn fixture() -> Fixture {
    let dir = TempDir::new().expect("temp dir");
    let path = dir.path().join("vault.cerberus");
    let clock = ManualClock::new(t0());
    let store = Store::open(
        OpenOptions {
            path: path.clone(),
            create: true,
        },
        Arc::new(clock.clone()),
    )
    .await
    .expect("open store");
    let vault = VaultId::generate();
    let keys = Arc::new(KeyTree::derive(&Vmk::generate().expect("vmk"), &vault).expect("keys"));
    let writer = Arc::new(AuditWriter::new(
        store.clone(),
        Arc::clone(&keys),
        vault,
        Arc::new(clock.clone()),
    ));
    Fixture {
        _dir: dir,
        path,
        store,
        keys,
        vault,
        clock,
        writer,
    }
}

fn sample(n: u64) -> AuditEvent {
    AuditEvent::new(EventType::ItemReveal, Actor::agent("agent-1"))
        .target("item", format!("item-{n}"))
        .detail("n", n)
}

async fn append_n(f: &Fixture, n: u64) {
    for i in 1..=n {
        f.clock.advance(SignedDuration::from_secs(1));
        assert_eq!(f.writer.append(&sample(i)).await.expect("append"), i);
    }
}

async fn raw(f: &Fixture) -> SqliteConnection {
    let options = SqliteConnectOptions::new().filename(&f.path);
    let mut conn = SqliteConnection::connect_with(&options)
        .await
        .expect("raw connection");
    for sql in [
        "DROP TRIGGER audit_events_no_update",
        "DROP TRIGGER audit_events_no_delete",
    ] {
        sqlx::query(sql)
            .execute(&mut conn)
            .await
            .expect("drop trigger");
    }
    conn
}

async fn row(f: &Fixture, seq: u64) -> AuditRow {
    f.store.audit_range(seq, 1).await.expect("range").remove(0)
}

fn flip(bytes: &[u8]) -> Vec<u8> {
    let mut out = bytes.to_vec();
    out[0] ^= 0x01;
    out
}

async fn verify(f: &Fixture) -> ChainReport {
    f.writer.verify().await.expect("verify")
}

#[tokio::test]
async fn clean_chain_verifies() {
    let f = fixture().await;
    assert_eq!(
        verify(&f).await,
        ChainReport::Ok {
            count: 0,
            first_seq: 0,
            last_seq: 0
        }
    );
    append_n(&f, 12).await;
    assert_eq!(
        verify(&f).await,
        ChainReport::Ok {
            count: 12,
            first_seq: 1,
            last_seq: 12
        }
    );
    assert_eq!(row(&f, 1).await.prev_hash, genesis_prev_hash(&f.vault));
}

#[tokio::test]
async fn changed_byte_is_found_at_its_seq() {
    for (column, kind) in [
        ("body_ct", BreakKind::HmacMismatch),
        ("hmac", BreakKind::HmacMismatch),
        ("prev_hash", BreakKind::PrevHashMismatch),
    ] {
        let f = fixture().await;
        append_n(&f, 6).await;
        let mut conn = raw(&f).await;
        let current = row(&f, 4).await;
        let old = match column {
            "body_ct" => current.body_ct.clone(),
            "hmac" => current.hmac.to_vec(),
            _ => current.prev_hash.to_vec(),
        };
        let sql = match column {
            "body_ct" => "UPDATE audit_events SET body_ct = ?1 WHERE seq = 4",
            "hmac" => "UPDATE audit_events SET hmac = ?1 WHERE seq = 4",
            _ => "UPDATE audit_events SET prev_hash = ?1 WHERE seq = 4",
        };
        sqlx::query(sql)
            .bind(flip(&old))
            .execute(&mut conn)
            .await
            .expect("tamper");
        assert_eq!(
            verify(&f).await,
            ChainReport::Broken { seq: 4, kind },
            "column {column}"
        );
    }
}

#[tokio::test]
async fn changed_time_is_found() {
    let f = fixture().await;
    append_n(&f, 4).await;
    let mut conn = raw(&f).await;
    sqlx::query("UPDATE audit_events SET occurred_at = occurred_at + 1 WHERE seq = 2")
        .execute(&mut conn)
        .await
        .expect("tamper");
    assert_eq!(
        verify(&f).await,
        ChainReport::Broken {
            seq: 2,
            kind: BreakKind::HmacMismatch
        }
    );
}

#[tokio::test]
async fn deleted_rows_are_found() {
    for (gone, expected) in [
        (
            1_u64,
            ChainReport::Broken {
                seq: 1,
                kind: BreakKind::MissingRow,
            },
        ),
        (
            3,
            ChainReport::Broken {
                seq: 3,
                kind: BreakKind::MissingRow,
            },
        ),
        (
            6,
            ChainReport::Broken {
                seq: 6,
                kind: BreakKind::HeadMismatch,
            },
        ),
    ] {
        let f = fixture().await;
        append_n(&f, 6).await;
        let mut conn = raw(&f).await;
        sqlx::query("DELETE FROM audit_events WHERE seq = ?1")
            .bind(i64::try_from(gone).expect("seq"))
            .execute(&mut conn)
            .await
            .expect("delete");
        assert_eq!(verify(&f).await, expected, "deleted seq {gone}");
    }
}

#[tokio::test]
async fn reordered_rows_are_found() {
    let f = fixture().await;
    append_n(&f, 5).await;
    let mut conn = raw(&f).await;
    for sql in [
        "UPDATE audit_events SET seq = 99 WHERE seq = 2",
        "UPDATE audit_events SET seq = 2 WHERE seq = 3",
        "UPDATE audit_events SET seq = 3 WHERE seq = 99",
    ] {
        sqlx::query(sql).execute(&mut conn).await.expect("swap");
    }
    assert!(matches!(
        verify(&f).await,
        ChainReport::Broken { seq: 2, .. }
    ));
}

#[tokio::test]
async fn changed_head_is_found() {
    let f = fixture().await;
    append_n(&f, 3).await;
    let mut conn = raw(&f).await;
    sqlx::query("UPDATE audit_head SET anchor_seq = 2")
        .execute(&mut conn)
        .await
        .expect("tamper");
    assert_eq!(
        verify(&f).await,
        ChainReport::Broken {
            seq: 3,
            kind: BreakKind::HeadMismatch
        }
    );
}

#[tokio::test]
async fn unreadable_body_is_found() {
    let f = fixture().await;
    append_n(&f, 2).await;
    let head = f.store.audit_head().await.expect("head").expect("some");
    let prev = head.last_entry_hash;
    let body_ct = vec![7_u8; 64];
    let hash = entry_hash(3, 5_000, &prev, &body_ct);
    let row = AuditRow {
        seq: 3,
        occurred_at: jiff::Timestamp::from_millisecond(5_000).expect("time"),
        prev_hash: prev,
        hmac: row_hmac(&f.keys.audit_key, &hash),
        body_ct,
    };
    let new_head = make_head(&f.keys.audit_key, 3, hash, 1, genesis_prev_hash(&f.vault));
    let mut tx = f.store.begin().await.expect("tx");
    tx.append_audit(&row, &new_head).await.expect("append");
    tx.commit().await.expect("commit");
    assert_eq!(
        verify(&f).await,
        ChainReport::Broken {
            seq: 3,
            kind: BreakKind::UnreadableBody
        }
    );
}

#[tokio::test]
async fn wrong_key_breaks_at_first_row() {
    let f = fixture().await;
    append_n(&f, 3).await;
    let other = KeyTree::derive(&Vmk::generate().expect("vmk"), &f.vault).expect("keys");
    let report = verify_chain(&f.store, &other, &f.vault)
        .await
        .expect("verify");
    assert!(matches!(report, ChainReport::Broken { .. }));
}

#[tokio::test]
async fn pending_events_join_the_chain_in_order() {
    let f = fixture().await;
    append_n(&f, 2).await;
    let agent = AgentId::generate();
    let request = RequestId::generate();
    let kinds = ["api.locked_call", "item.expire", "auth.failed"];
    for (i, kind) in kinds.iter().enumerate() {
        let at = t0()
            .checked_add(SignedDuration::from_secs(
                100 + i64::try_from(i).expect("index"),
            ))
            .expect("time");
        let row = AuditPendingRow {
            occurred_at: at,
            event_type: (*kind).to_owned(),
            agent_id: (i == 0).then_some(agent),
            target_id: (i == 1).then(|| "item-x".to_owned()),
            result_code: if i == 0 { "vault_locked" } else { "ok" }.to_owned(),
            route: (i == 0).then(|| "/v1/credentials/{id}/reveal".to_owned()),
            request_id: (i == 0).then_some(request),
        };
        f.store.push_audit_pending(&row, 10).await.expect("push");
    }
    // Over the cap: counted as overflow only.
    let extra = AuditPendingRow {
        occurred_at: t0(),
        event_type: "auth.failed".to_owned(),
        agent_id: None,
        target_id: None,
        result_code: "unauthenticated".to_owned(),
        route: None,
        request_id: None,
    };
    f.store.push_audit_pending(&extra, 3).await.expect("push");

    assert_eq!(f.writer.drain_pending().await.expect("drain"), 3);
    assert_eq!(
        verify(&f).await,
        ChainReport::Ok {
            count: 6,
            first_seq: 1,
            last_seq: 6
        }
    );
    let mut out = Vec::new();
    f.writer
        .export_jsonl(Actor::operator("op-1"), &mut out)
        .await
        .expect("export");
    let lines: Vec<serde_json::Value> = String::from_utf8(out)
        .expect("utf8")
        .lines()
        .map(|line| serde_json::from_str(line).expect("json"))
        .collect();
    let types: Vec<&str> = lines
        .iter()
        .map(|l| l["body"]["type"].as_str().expect("type"))
        .collect();
    assert_eq!(
        types,
        [
            "item.reveal",
            "item.reveal",
            "api.locked_call",
            "item.expire",
            "auth.failed",
            "audit.pending_overflow"
        ]
    );
    assert_eq!(lines[2]["body"]["details"]["recorded_while_locked"], true);
    assert_eq!(lines[2]["body"]["actor"]["kind"], "agent");
    assert_eq!(lines[3]["body"]["target"]["kind"], "item");
    assert_eq!(lines[3]["body"]["actor"]["kind"], "system");
    assert_eq!(lines[5]["body"]["details"]["dropped"], 1);
    assert_eq!(lines[2]["occurred_at"], 1_767_225_700_000_i64);
    // The list is empty now.
    assert_eq!(f.writer.drain_pending().await.expect("drain"), 0);
    assert_eq!(
        f.store
            .audit_head()
            .await
            .expect("head")
            .expect("some")
            .last_seq,
        7
    );
}

fn pending_row(n: i64) -> AuditPendingRow {
    AuditPendingRow {
        occurred_at: t0()
            .checked_add(SignedDuration::from_secs(n))
            .expect("time"),
        event_type: "api.locked_call".to_owned(),
        agent_id: None,
        target_id: None,
        result_code: "vault_locked".to_owned(),
        route: Some("/v1/credentials/{id}/reveal".to_owned()),
        request_id: None,
    }
}

#[tokio::test]
async fn a_failed_drain_leaves_the_pending_rows_and_the_chain_alone() {
    let f = fixture().await;
    for n in 1..=3 {
        f.store
            .push_audit_pending(&pending_row(n), 2)
            .await
            .expect("push");
    }
    // A trigger that refuses every insert: the first chained event fails after the pending rows
    // were taken, so the drain fails before its commit. (Before T27 a stray row at seq 1 did this;
    // now the writer marks such a row as a break and goes on, AUD-1.)
    let mut conn = raw(&f).await;
    sqlx::query(
        "CREATE TRIGGER test_no_insert BEFORE INSERT ON audit_events \
         BEGIN SELECT RAISE(ABORT, 'test'); END",
    )
    .execute(&mut conn)
    .await
    .expect("trigger");
    conn.close().await.expect("close");

    assert!(f.writer.drain_pending().await.is_err());
    // The rows and the overflow counter are still there, and nothing was chained.
    let take = f.store.take_audit_pending().await.expect("take");
    let (rows, overflow) = (take.rows, take.overflow);
    assert_eq!(rows.len(), 2);
    assert_eq!(overflow, 1);
    assert!(f.store.audit_head().await.expect("head").is_none());
    assert!(f.store.audit_range(1, 10).await.expect("range").is_empty());
}

#[tokio::test]
async fn concurrent_appends_keep_one_chain() {
    let f = fixture().await;
    let mut tasks = Vec::new();
    for i in 0..24_u64 {
        let writer = Arc::clone(&f.writer);
        tasks.push(tokio::spawn(async move { writer.append(&sample(i)).await }));
    }
    let mut seqs = Vec::new();
    for task in tasks {
        seqs.push(task.await.expect("join").expect("append"));
    }
    seqs.sort_unstable();
    assert_eq!(seqs, (1..=24).collect::<Vec<u64>>());
    assert_eq!(
        verify(&f).await,
        ChainReport::Ok {
            count: 24,
            first_seq: 1,
            last_seq: 24
        }
    );
}

#[tokio::test]
async fn export_holds_metadata_and_no_secret() {
    let f = fixture().await;
    let marker = SecretString::new("MARKER-s3cr3t-9f3a71".to_owned());
    // A caller can only pass metadata: the secret type does not convert into a detail.
    let event = AuditEvent::new(EventType::ItemReveal, Actor::agent("agent-1"))
        .target("item", "item-1")
        .detail("value_length", marker.expose_secret().len());
    f.writer.append(&event).await.expect("append");
    let mut out = Vec::new();
    let lines = f
        .writer
        .export_jsonl(Actor::operator("op-1"), &mut out)
        .await
        .expect("export");
    assert_eq!(lines, 1);
    let text = String::from_utf8(out).expect("utf8");
    let first: serde_json::Value =
        serde_json::from_str(text.lines().next().expect("line")).expect("json");
    assert_eq!(first["seq"], 1);
    assert_eq!(first["body"]["target"]["id"], "item-1");
    assert_eq!(first["prev_hash"].as_str().expect("hex").len(), 64);
    assert!(!text.contains("MARKER-s3cr3t"));
    f.store.clone().close().await;
    for suffix in ["", "-wal"] {
        let mut name = f.path.clone().into_os_string();
        name.push(suffix);
        if let Ok(bytes) = std::fs::read(&name) {
            assert!(!bytes.windows(13).any(|w| w == b"MARKER-s3cr3t"));
        }
    }
}

#[tokio::test]
async fn sealed_body_hides_metadata_in_the_file() {
    let f = fixture().await;
    let event = AuditEvent::new(EventType::ItemCreate, Actor::operator("op-1"))
        .target("item", "item-1")
        .detail("title", "Visible-Title-Marker");
    f.writer.append(&event).await.expect("append");
    let stored = row(&f, 1).await;
    assert!(
        !stored
            .body_ct
            .windows(20)
            .any(|w| w == b"Visible-Title-Marker")
    );
    let blobs = Blobs::new(&f.vault, &f.keys);
    let plain = blobs.open_audit_body(1, &stored.body_ct).expect("open");
    assert!(
        plain
            .expose_secret()
            .windows(20)
            .any(|w| w == b"Visible-Title-Marker")
    );
}

#[tokio::test]
async fn prune_keeps_a_valid_chain() {
    let f = fixture().await;
    for i in 1..=6_u64 {
        f.clock.advance(SignedDuration::from_hours(24));
        f.writer.append(&sample(i)).await.expect("append");
    }
    // Rows are at day 1..6. Retention 3 days at day 6 keeps day 3 on, so seq 1 and 2 go.
    let deleted = f.writer.prune(3, Actor::system()).await.expect("prune");
    assert_eq!(deleted, 2);
    assert_eq!(
        verify(&f).await,
        ChainReport::Ok {
            count: 5,
            first_seq: 3,
            last_seq: 7
        }
    );
    let mut out = Vec::new();
    f.writer
        .export_jsonl(Actor::system(), &mut out)
        .await
        .expect("export");
    let text = String::from_utf8(out).expect("utf8");
    assert!(text.lines().next().expect("line").contains("\"seq\":3"));
    assert!(text.contains("audit.prune"));
    // Nothing left to prune.
    assert_eq!(f.writer.prune(3, Actor::system()).await.expect("prune"), 0);
    // A break in the kept rows is still found after a prune.
    let mut conn = raw(&f).await;
    let current = row(&f, 5).await;
    sqlx::query("UPDATE audit_events SET body_ct = ?1 WHERE seq = 5")
        .bind(flip(&current.body_ct))
        .execute(&mut conn)
        .await
        .expect("tamper");
    assert_eq!(
        verify(&f).await,
        ChainReport::Broken {
            seq: 5,
            kind: BreakKind::HmacMismatch
        }
    );
    assert!(matches!(
        f.writer.prune(1, Actor::system()).await,
        Err(crate::CoreError::Corrupt)
    ));
}

#[tokio::test]
async fn prune_always_keeps_the_newest_row() {
    let f = fixture().await;
    append_n(&f, 3).await;
    f.clock.advance(SignedDuration::from_hours(24 * 400));
    assert_eq!(
        f.writer.prune(365, Actor::system()).await.expect("prune"),
        2
    );
    assert!(matches!(
        verify(&f).await,
        ChainReport::Ok { first_seq: 3, .. }
    ));
}

#[test]
fn long_text_is_cut() {
    let long = "x".repeat(2_000);
    let event = sample(1).detail("reason", long.as_str());
    let kept = event.details["reason"].as_str().expect("text");
    assert_eq!(kept.chars().count(), MAX_TEXT_CHARS);
    let nested = sample(1).detail("a", serde_json::json!({ "b": ["é".repeat(900)] }));
    assert_eq!(
        nested.details["a"]["b"][0]
            .as_str()
            .expect("text")
            .chars()
            .count(),
        MAX_TEXT_CHARS
    );
}

#[test]
fn catalog_is_unique_parseable_and_documented() {
    let mut names: Vec<&str> = EventType::ALL.iter().map(|e| e.as_str()).collect();
    for kind in EventType::ALL {
        assert_eq!(kind.as_str().parse::<EventType>(), Ok(*kind));
    }
    names.sort_unstable();
    let before = names.len();
    names.dedup();
    assert_eq!(before, names.len());
    assert!("nope".parse::<EventType>().is_err());
    let doc = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/reference/audit-events.md"
    ))
    .expect("catalog doc");
    for kind in EventType::ALL {
        assert!(
            doc.contains(&format!("| `{}` |", kind.as_str())),
            "{} missing from docs/reference/audit-events.md",
            kind.as_str()
        );
    }
}

/// AUD-1: the exploit of the audit report. Rows at the end are cut and the head is moved back
/// to the last kept row, with its old MAC. The next append must not sign that head again.
#[tokio::test]
async fn a_cut_tail_with_an_edited_head_is_not_signed_again() {
    let f = fixture().await;
    append_n(&f, 10).await;
    let cut = row(&f, 8).await;
    let mut conn = raw(&f).await;
    sqlx::query("DELETE FROM audit_events WHERE seq >= 8")
        .execute(&mut conn)
        .await
        .expect("cut");
    sqlx::query("UPDATE audit_head SET last_seq = 7, last_entry_hash = ?1")
        .bind(cut.prev_hash.as_slice())
        .execute(&mut conn)
        .await
        .expect("edit head");
    conn.close().await.expect("close");
    f.writer.append(&sample(11)).await.expect("append");
    assert!(
        matches!(verify(&f).await, ChainReport::Broken { .. }),
        "the cut must stay visible"
    );
    // Later appends keep the break visible.
    f.writer.append(&sample(12)).await.expect("append");
    assert!(matches!(verify(&f).await, ChainReport::Broken { .. }));
}

/// AUD-1: a cut tail with the head left as it is (its MAC still good) is not hidden either.
#[tokio::test]
async fn a_cut_tail_under_a_good_head_is_not_hidden() {
    let f = fixture().await;
    append_n(&f, 6).await;
    let mut conn = raw(&f).await;
    sqlx::query("DELETE FROM audit_events WHERE seq >= 5")
        .execute(&mut conn)
        .await
        .expect("cut");
    conn.close().await.expect("close");
    f.writer.append(&sample(7)).await.expect("append");
    assert!(matches!(verify(&f).await, ChainReport::Broken { .. }));
}

/// NEW-2: a break mark is permanent, so it must not hide a later break. After a cut tail and its
/// mark, an edit of a row after the mark is reported at that row; a gap after it as well.
#[tokio::test]
async fn new2_a_break_mark_does_not_hide_a_later_break() {
    let f = fixture().await;
    append_n(&f, 6).await;
    let mut conn = raw(&f).await;
    sqlx::query("DELETE FROM audit_events WHERE seq >= 5")
        .execute(&mut conn)
        .await
        .expect("cut");
    for n in 7..=10 {
        f.writer.append(&sample(n)).await.expect("append");
    }
    // Rows 1 to 4 are left; the mark is at the old head seq + 1 (7) and the new events are 8 to 11.
    assert_eq!(
        verify(&f).await,
        ChainReport::Broken {
            seq: 5,
            kind: BreakKind::MissingRow
        },
        "with nothing else wrong the cut is the report"
    );
    let current = row(&f, 9).await;
    sqlx::query("UPDATE audit_events SET body_ct = ?1 WHERE seq = 9")
        .bind(flip(&current.body_ct))
        .execute(&mut conn)
        .await
        .expect("tamper");
    assert_eq!(
        verify(&f).await,
        ChainReport::Broken {
            seq: 9,
            kind: BreakKind::HmacMismatch
        }
    );
    sqlx::query("UPDATE audit_events SET body_ct = ?1 WHERE seq = 9")
        .bind(current.body_ct.as_slice())
        .execute(&mut conn)
        .await
        .expect("restore");
    sqlx::query("DELETE FROM audit_events WHERE seq = 10")
        .execute(&mut conn)
        .await
        .expect("delete a middle row");
    conn.close().await.expect("close");
    assert_eq!(
        verify(&f).await,
        ChainReport::Broken {
            seq: 10,
            kind: BreakKind::MissingRow
        }
    );
}

/// NEW-2: the same after a mark with no gap (a changed head): the mark is the report until a row
/// after it is edited.
#[tokio::test]
async fn new2_an_edit_after_a_head_mark_is_reported() {
    let f = fixture().await;
    append_n(&f, 5).await;
    let mut conn = raw(&f).await;
    sqlx::query("UPDATE audit_head SET head_hmac = zeroblob(32)")
        .execute(&mut conn)
        .await
        .expect("edit head");
    for n in 6..=8 {
        f.writer.append(&sample(n)).await.expect("append");
    }
    // The mark is at 6, the new events are 7 to 9.
    assert_eq!(
        verify(&f).await,
        ChainReport::Broken {
            seq: 6,
            kind: BreakKind::HeadMismatch
        }
    );
    let current = row(&f, 8).await;
    sqlx::query("UPDATE audit_events SET body_ct = ?1 WHERE seq = 8")
        .bind(flip(&current.body_ct))
        .execute(&mut conn)
        .await
        .expect("tamper");
    conn.close().await.expect("close");
    assert_eq!(
        verify(&f).await,
        ChainReport::Broken {
            seq: 8,
            kind: BreakKind::HmacMismatch
        }
    );
}

/// AUD-1: a deleted head row with rows left does not start a second chain at seq 1.
#[tokio::test]
async fn a_deleted_head_does_not_restart_the_chain() {
    let f = fixture().await;
    append_n(&f, 3).await;
    let mut conn = raw(&f).await;
    sqlx::query("DELETE FROM audit_head")
        .execute(&mut conn)
        .await
        .expect("delete head");
    conn.close().await.expect("close");
    f.writer.append(&sample(4)).await.expect("append");
    assert!(matches!(verify(&f).await, ChainReport::Broken { .. }));
}

/// AUD-9: one malformed pending row is skipped and counted; the other rows join the chain.
#[tokio::test]
async fn a_malformed_pending_row_is_skipped_and_counted() {
    let f = fixture().await;
    f.store
        .push_audit_pending(&pending_row(1), 10)
        .await
        .expect("push");
    let mut conn = raw(&f).await;
    for sql in [
        "INSERT INTO audit_pending (occurred_at, event_type, agent_id, result_code) \
         VALUES (2, 'auth.failed', 'not-a-uuid', 'unauthenticated')",
        "INSERT INTO audit_pending (occurred_at, event_type, result_code) \
         VALUES (3, 'item.reveal', 'ok')",
    ] {
        sqlx::query(sql).execute(&mut conn).await.expect("insert");
    }
    conn.close().await.expect("close");
    f.store
        .push_audit_pending(&pending_row(4), 10)
        .await
        .expect("push");
    assert_eq!(f.writer.drain_pending().await.expect("drain"), 2);
    let blobs = Blobs::new(&f.vault, &f.keys);
    let rows = f.store.audit_range(1, 10).await.expect("range");
    let bodies: Vec<AuditEvent> = rows
        .iter()
        .map(|r| open_audit_body(&blobs, r).expect("body"))
        .collect();
    let types: Vec<&str> = bodies.iter().map(|b| b.event_type.as_str()).collect();
    assert_eq!(
        types,
        [
            "api.locked_call",
            "api.locked_call",
            "audit.pending_overflow"
        ]
    );
    assert_eq!(bodies[2].details["malformed"], 2);
    assert_eq!(bodies[2].details["dropped"], 0);
    assert!(matches!(verify(&f).await, ChainReport::Ok { count: 3, .. }));
}
