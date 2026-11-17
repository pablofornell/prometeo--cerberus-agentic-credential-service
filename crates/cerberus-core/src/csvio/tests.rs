//! Tests of the CSV import and export. Every value in the fixtures is fake.

use std::collections::{BTreeMap, BTreeSet};

use cerberus_crypto::SecretString;
use cerberus_types::{Environment, ItemKind, OperatorRole, WorkspaceId};
use proptest::prelude::*;

use super::plan::make_plan;
use super::*;
use crate::agent_api::tests::{Fx, login};
use crate::error::CoreError;
use crate::index::CreatedBy;
use crate::items::{ItemFilter, Payload};
use crate::vault::KeyCustody;

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/tests/fixtures/csv/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(path).expect("fixture")
}

fn options(ws: WorkspaceId, source: CsvSource) -> ImportOptions {
    ImportOptions {
        source,
        workspace_id: ws,
        environment: Environment::Dev,
        role_label: Some("imported".to_owned()),
        mapping: BTreeMap::new(),
        duplicates: DuplicatePolicy::Skip,
    }
}

fn preview_of(name: &str, source: CsvSource) -> ImportPreview {
    let table = parse_table(&fixture(name)).expect("parse");
    make_plan(
        &table,
        &options(WorkspaceId::generate(), source),
        &BTreeSet::new(),
    )
    .expect("plan")
    .preview
}

// ---- parser ----

#[test]
fn bom_crlf_quoted_newlines_and_doubled_quotes() {
    let text = "\u{feff}a,b\r\n\"x\r\ny\",\"say \"\"hi\"\"\"\r\n1,2\r\n";
    let table = parse_table(text.as_bytes()).expect("parse");
    assert_eq!(table.headers, ["a", "b"]);
    assert_eq!(table.rows.len(), 2);
    assert_eq!(table.rows[0].cells[0].as_str(), "x\r\ny");
    assert_eq!(table.rows[0].cells[1].as_str(), "say \"hi\"");
}

#[test]
fn delimiter_comes_from_the_header_line() {
    let table = parse_table(b"a;b\n1;2\n").expect("parse");
    assert_eq!(table.rows[0].cells.len(), 2);
    let table = parse_table(b"a\tb\n1\t2\n").expect("parse");
    assert_eq!(table.rows[0].cells.len(), 2);
}

#[test]
fn bad_files_have_clear_errors() {
    assert_eq!(
        parse_table(b"a,b\n\xff\xfe,1\n").unwrap_err(),
        CsvError::NotUtf8
    );
    assert_eq!(
        parse_table(b"\xff\xfea\x00,\x00b\x00").unwrap_err(),
        CsvError::Utf16
    );
    assert_eq!(parse_table(b"").unwrap_err(), CsvError::Empty);
    assert_eq!(parse_table(b"\n\n").unwrap_err(), CsvError::Empty);
    let big = vec![b'a'; MAX_FILE_BYTES + 1];
    assert_eq!(parse_table(&big).unwrap_err(), CsvError::TooLarge);
    let mut rows = String::from("a\n");
    for _ in 0..=MAX_ROWS {
        rows.push_str("x\n");
    }
    assert_eq!(
        parse_table(rows.as_bytes()).unwrap_err(),
        CsvError::TooManyRows
    );
    let header = (0..=MAX_COLUMNS)
        .map(|i| format!("c{i}"))
        .collect::<Vec<_>>()
        .join(",");
    assert_eq!(
        parse_table(header.as_bytes()).unwrap_err(),
        CsvError::TooManyColumns
    );
    let cell = format!("a\n{}\n", "x".repeat(MAX_CELL_BYTES + 1));
    assert_eq!(
        parse_table(cell.as_bytes()).unwrap_err(),
        CsvError::CellTooLarge
    );
    let ok = format!("a\n{}\n", "x".repeat(MAX_CELL_BYTES));
    assert!(parse_table(ok.as_bytes()).is_ok());
}

#[test]
fn the_error_text_never_holds_a_cell() {
    let secret = "zq-fake-cell-value";
    let text = format!("a,b\n{secret},\u{0}\n");
    let preview = make_plan(
        &parse_table(text.as_bytes()).expect("parse"),
        &options(WorkspaceId::generate(), CsvSource::Generic),
        &BTreeSet::new(),
    )
    .expect("plan")
    .preview;
    assert!(!format!("{preview:?}").contains(secret));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..600)) {
        if let Ok(table) = parse_table(&bytes) {
            for source in [CsvSource::Auto, CsvSource::Generic, CsvSource::Bitwarden, CsvSource::Chrome] {
                let _ = make_plan(&table, &options(WorkspaceId::generate(), source), &BTreeSet::new());
            }
        }
    }

    #[test]
    fn arbitrary_text_with_csv_characters_never_panics(text in "[a-z0-9,;\"\\r\\n\\t '=@+-]{0,300}") {
        if let Ok(table) = parse_table(text.as_bytes()) {
            let plan = make_plan(&table, &options(WorkspaceId::generate(), CsvSource::Auto), &BTreeSet::new());
            if let Ok(plan) = plan
                && plan.preview.source.is_some()
            {
                prop_assert_eq!(
                    plan.preview.importable as usize + plan.preview.problem_count as usize
                        + plan.preview.duplicate_count as usize - plan.preview.renamed as usize,
                    table.rows.len()
                );
            }
        }
    }

    #[test]
    fn the_guard_is_undone_exactly(cell in "[a-z'=+@\\t\\r -]{0,12}") {
        let guarded = guard_cell(&cell);
        prop_assert_eq!(unguard_cell(&guarded), cell.as_str());
        let first = guarded.chars().next();
        prop_assert!(!matches!(first, Some('=' | '+' | '-' | '@' | '\t' | '\r')));
    }
}

#[test]
fn formula_cells_get_a_leading_quote() {
    for bad in ["=1+1", "+1", "-1", "@SUM(A1)", "\tx", "\rx", "'=x"] {
        assert!(guard_cell(bad).starts_with('\''), "{bad:?}");
    }
    for fine in ["plain", "", "a=b", "'quoted", "1-2"] {
        assert_eq!(guard_cell(fine), fine);
    }
}

// ---- formats ----

#[test]
fn bitwarden_fixture() {
    let p = preview_of("bitwarden.csv", CsvSource::Auto);
    assert_eq!(p.source, Some(CsvSource::Bitwarden));
    assert_eq!(p.total_rows, 5);
    assert_eq!(p.importable, 4);
    assert_eq!(p.problem_count, 1, "the card");
    assert_eq!(p.problems[0].code, ProblemCode::UnsupportedKind);
    assert_eq!(p.problems[0].row, 3);
    assert_eq!(
        (p.duplicate_count, p.renamed),
        (1, 1),
        "same title in the file"
    );
    assert_eq!(p.notes_dropped, 1);
    assert!(p.by_kind.contains(&(ItemKind::Note, 1)));
    assert!(p.by_kind.contains(&(ItemKind::WebLogin, 3)));
}

#[test]
fn onepassword_fixture() {
    let p = preview_of("onepassword.csv", CsvSource::Auto);
    assert_eq!(p.source, Some(CsvSource::OnePassword));
    assert_eq!((p.total_rows, p.importable, p.problem_count), (2, 2, 0));
}

#[test]
fn keepassxc_fixture() {
    let p = preview_of("keepassxc.csv", CsvSource::Auto);
    assert_eq!(p.source, Some(CsvSource::KeePassXc));
    assert_eq!((p.total_rows, p.importable), (2, 1));
    assert_eq!(p.problems[0].code, ProblemCode::MissingSecret);
}

#[test]
fn chrome_fixture() {
    let p = preview_of("chrome.csv", CsvSource::Auto);
    assert_eq!(p.source, Some(CsvSource::Chrome));
    assert_eq!((p.total_rows, p.importable, p.problem_count), (3, 2, 1));
    assert_eq!(p.problems[0].code, ProblemCode::InvalidValue);
    assert_eq!(p.problems[0].field.as_deref(), Some("payload.username"));
}

#[test]
fn firefox_fixture() {
    let p = preview_of("firefox.csv", CsvSource::Auto);
    assert_eq!(p.source, Some(CsvSource::Firefox));
    assert_eq!(
        (p.total_rows, p.importable),
        (1, 1),
        "title comes from the host"
    );
}

#[test]
fn generic_fixture_with_bom_and_crlf() {
    let p = preview_of("generic_bom_crlf.csv", CsvSource::Auto);
    assert_eq!(p.source, Some(CsvSource::Generic));
    assert_eq!((p.total_rows, p.importable), (2, 2));
    assert!(p.by_kind.contains(&(ItemKind::ApiKey, 1)));
}

#[test]
fn an_unknown_header_needs_a_mapping() {
    let bytes = fixture("mapped_semicolon.csv");
    let table = parse_table(&bytes).expect("parse");
    let ws = WorkspaceId::generate();
    let none = make_plan(&table, &options(ws, CsvSource::Auto), &BTreeSet::new()).expect("plan");
    assert_eq!(none.preview.source, None);
    assert_eq!(none.preview.columns, ["Label", "User name", "Pass", "Type"]);
    let mut opts = options(ws, CsvSource::Generic);
    let unmapped = make_plan(&table, &opts, &BTreeSet::new()).expect("plan");
    assert_eq!(unmapped.preview.importable, 0, "no title column");
    opts.mapping = [
        (Field::Title, "Label"),
        (Field::Username, "User name"),
        (Field::Password, "Pass"),
        (Field::Kind, "Type"),
    ]
    .into_iter()
    .map(|(f, c)| (f, c.to_owned()))
    .collect();
    let mapped = make_plan(&table, &opts, &BTreeSet::new()).expect("plan");
    assert_eq!(mapped.preview.importable, 2);
    assert!(
        mapped
            .preview
            .by_kind
            .contains(&(ItemKind::SessionToken, 1))
    );
    opts.mapping
        .insert(Field::Notes, "No such column".to_owned());
    assert!(matches!(
        make_plan(&table, &opts, &BTreeSet::new()),
        Err(CoreError::Validation(_))
    ));
}

#[test]
fn existing_titles_are_skipped_or_renamed() {
    let table = parse_table(&fixture("onepassword.csv")).expect("parse");
    let ws = WorkspaceId::generate();
    let existing: BTreeSet<String> = ["fake bank".to_owned()].into();
    let skip = make_plan(&table, &options(ws, CsvSource::Auto), &existing).expect("plan");
    assert_eq!(
        (skip.preview.importable, skip.preview.duplicate_count),
        (1, 1)
    );
    assert!(!skip.preview.duplicates[0].in_file);
    assert!(!skip.preview.duplicates[0].renamed);
    let mut opts = options(ws, CsvSource::Auto);
    opts.duplicates = DuplicatePolicy::Rename;
    let rename = make_plan(&table, &opts, &existing).expect("plan");
    assert_eq!((rename.preview.importable, rename.preview.renamed), (2, 1));
    assert_eq!(rename.items[0].title, "Fake Bank (2)");
}

// ---- service ----

async fn import(fx: &Fx, ws: WorkspaceId, name: &str) -> Result<ImportReport, CoreError> {
    fx.service
        .csv_import(&fx.owner, &fixture(name), &options(ws, CsvSource::Auto))
        .await
}

#[tokio::test]
async fn import_makes_items_and_audits_counts_only() {
    let fx = Fx::new().await;
    let ws = fx.workspace("shop").await;
    let report = import(&fx, ws, "bitwarden.csv").await.unwrap();
    assert_eq!(
        (
            report.imported,
            report.skipped_problems,
            report.renamed,
            report.notes_dropped
        ),
        (4, 1, 1, 1)
    );
    let items = fx
        .service
        .list_items(&fx.owner, ItemFilter::default())
        .await
        .unwrap();
    assert_eq!(items.len(), 4);
    let mail = items.iter().find(|i| i.title == "Fake Mail").expect("mail");
    assert_eq!(mail.role_label.as_deref(), Some("imported"));
    assert_eq!(mail.environment, Environment::Dev);
    assert!(mail.has_totp);
    assert!(items.iter().any(|i| i.title == "Fake Mail (2)"));
    assert!(items.iter().any(|i| i.title == "noname.example.test"));
    let revealed = fx.service.reveal_item(&fx.owner, mail.id).await.unwrap();
    let Payload::WebLogin { password, .. } = revealed.payload else {
        panic!("a login");
    };
    assert_eq!(password.expose_secret(), "zq-fake-pass-1");

    // The audit holds counts, no titles, no secrets, no file content.
    let rows = fx
        .service
        .audit_query(
            &fx.owner,
            crate::admin::AuditQuery {
                limit: 1000,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let event = rows
        .iter()
        .find(|e| e.event.event_type == "items.import")
        .expect("items.import");
    assert_eq!(event.event.details["imported"], 4);
    let text = serde_json::to_string(&rows.iter().map(|r| &r.event).collect::<Vec<_>>()).unwrap();
    for leak in ["Fake Mail", "zq-fake", "example.test", "fake.user"] {
        assert!(!text.contains(leak), "{leak}");
    }
    // A second import of the same file adds only what the first renamed away.
    let again = import(&fx, ws, "bitwarden.csv").await.unwrap_err();
    assert!(
        matches!(again, CoreError::Validation(_)),
        "nothing new to import"
    );
}

#[tokio::test]
async fn a_failing_batch_writes_nothing() {
    let fx = Fx::new().await;
    let ws = fx.workspace("shop").await;
    let before = fx
        .service
        .list_items(&fx.owner, ItemFilter::default())
        .await
        .unwrap()
        .len();
    let table = parse_table(&fixture("generic_bom_crlf.csv")).unwrap();
    let plan = make_plan(&table, &options(ws, CsvSource::Auto), &BTreeSet::new()).unwrap();
    let mut inputs = plan.items;
    assert_eq!(inputs.len(), 2);
    // The second item repeats the title of the first: the batch must stop with no item made.
    inputs[1].title = inputs[0].title.clone();
    let mut guard = fx.service.unlocked_mut().await.unwrap();
    let result = fx
        .service
        .insert_items_batch(
            &mut guard,
            inputs,
            CreatedBy::Operator(fx.owner.operator_id),
        )
        .await;
    drop(guard);
    assert!(matches!(result, Err(CoreError::Conflict)));
    let after = fx
        .service
        .list_items(&fx.owner, ItemFilter::default())
        .await
        .unwrap()
        .len();
    assert_eq!(before, after);

    // An item that fails validation in the middle of a batch.
    let mut inputs = make_plan(&table, &options(ws, CsvSource::Auto), &BTreeSet::new())
        .unwrap()
        .items;
    inputs[1].title = String::new();
    let mut guard = fx.service.unlocked_mut().await.unwrap();
    let result = fx
        .service
        .insert_items_batch(
            &mut guard,
            inputs,
            CreatedBy::Operator(fx.owner.operator_id),
        )
        .await;
    drop(guard);
    assert!(matches!(result, Err(CoreError::Validation(_))));
    assert_eq!(
        fx.service
            .list_items(&fx.owner, ItemFilter::default())
            .await
            .unwrap()
            .len(),
        before
    );
    // The same file imports fine afterwards, so nothing half-written stands in the way.
    assert_eq!(
        import(&fx, ws, "generic_bom_crlf.csv")
            .await
            .unwrap()
            .imported,
        2
    );
}

#[tokio::test]
async fn a_workspace_that_does_not_exist_is_refused() {
    let fx = Fx::new().await;
    let result = import(&fx, WorkspaceId::generate(), "chrome.csv").await;
    assert!(matches!(result, Err(CoreError::Validation(_))));
}

#[tokio::test]
async fn roles_come_from_the_session() {
    let fx = Fx::new().await;
    let ws = fx.workspace("shop").await;
    let phrase = "lantern quartz meadow ripple 3";
    for (label, role) in [
        ("Viewer", OperatorRole::Viewer),
        ("Operator", OperatorRole::Operator),
    ] {
        let id = fx
            .service
            .add_operator(
                &fx.owner,
                label.to_owned(),
                role,
                SecretString::new(phrase.to_owned()),
            )
            .await
            .unwrap();
        fx.lock().await;
        let mut ctx = fx
            .service
            .unlock_with_phrase(id, SecretString::new(phrase.to_owned()))
            .await
            .unwrap();
        // A context that claims the owner role still has the session role.
        ctx.role = OperatorRole::Owner;
        let opts = options(ws, CsvSource::Auto);
        let bytes = fixture("chrome.csv");
        let preview = fx.service.csv_preview(&ctx, &bytes, &opts).await;
        let imported = fx.service.csv_import(&ctx, &bytes, &opts).await;
        let exported = fx.service.csv_export(&ctx, None).await;
        if role == OperatorRole::Viewer {
            assert!(matches!(preview, Err(CoreError::RoleNotAllowed)));
            assert!(matches!(imported, Err(CoreError::RoleNotAllowed)));
        } else {
            assert!(preview.is_ok());
            assert_eq!(imported.unwrap().imported, 2);
        }
        assert!(
            matches!(exported, Err(CoreError::RoleNotAllowed)),
            "{label}"
        );
        fx.lock().await;
        fx.unlock().await;
    }
    assert!(fx.service.csv_export(&fx.owner, None).await.is_ok());
}

#[tokio::test]
async fn export_needs_an_unlocked_vault() {
    let fx = Fx::new().await;
    fx.lock().await;
    assert!(matches!(
        fx.service.csv_export(&fx.owner, None).await,
        Err(CoreError::Locked)
    ));
}

#[tokio::test]
async fn export_guards_formulas_and_round_trips() {
    let fx = Fx::new().await;
    let ws = fx.workspace("shop").await;
    let other = fx.workspace("other").await;
    let evil = "=cmd|' /C calc'!A0";
    fx.item(login(ws, "=Evil title", Environment::Prod, "+user", evil))
        .await;
    fx.item(login(
        ws,
        "Plain \"quoted\", title",
        Environment::Dev,
        "u",
        "line1\nline2",
    ))
    .await;
    fx.item(login(
        other,
        "Other workspace",
        Environment::Dev,
        "u",
        "zq-fake-other",
    ))
    .await;

    let all = fx.service.csv_export(&fx.owner, None).await.unwrap();
    assert_eq!(all.count, 3);
    let scoped = fx.service.csv_export(&fx.owner, Some(ws)).await.unwrap();
    assert_eq!(scoped.count, 2);
    assert!(!String::from_utf8_lossy(&scoped.bytes).contains("zq-fake-other"));

    // Every data cell that would start a formula starts with a quote instead.
    let text = String::from_utf8(scoped.bytes.to_vec()).unwrap();
    let mut reader = csv::Reader::from_reader(text.as_bytes());
    let mut cells = 0;
    for record in reader.records() {
        for cell in &record.unwrap() {
            cells += 1;
            let first = cell.chars().next();
            assert!(
                !matches!(first, Some('=' | '+' | '-' | '@' | '\t' | '\r')),
                "{cell:?}"
            );
        }
    }
    assert!(cells > 0);
    assert!(text.contains("'=cmd|"));
    assert!(text.contains("'+user"));

    // The file imports again as a Cerberus file, with the original values.
    let fresh = fx.workspace("fresh").await;
    let report = fx
        .service
        .csv_import(&fx.owner, &scoped.bytes, &options(fresh, CsvSource::Auto))
        .await
        .unwrap();
    assert_eq!(report.imported, 2);
    let items = fx
        .service
        .list_items(
            &fx.owner,
            ItemFilter {
                workspace_id: Some(fresh),
                ..ItemFilter::default()
            },
        )
        .await
        .unwrap();
    let item = items
        .iter()
        .find(|i| i.title == "=Evil title")
        .expect("title");
    assert_eq!(item.environment, Environment::Prod);
    let Payload::WebLogin {
        username, password, ..
    } = fx
        .service
        .reveal_item(&fx.owner, item.id)
        .await
        .unwrap()
        .payload
    else {
        panic!("a login");
    };
    assert_eq!(
        (username.expose_secret(), password.expose_secret()),
        ("+user", evil)
    );

    let types = fx.audit_types().await;
    assert!(types.contains(&"items.export".to_owned()));
    let rows = fx
        .service
        .audit_query(
            &fx.owner,
            crate::admin::AuditQuery {
                limit: 1000,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let text = serde_json::to_string(&rows.iter().map(|r| &r.event).collect::<Vec<_>>()).unwrap();
    assert!(!text.contains("zq-fake") && !text.contains("Evil"));
}

#[test]
fn kind_names_are_forgiving() {
    use super::rows::kind_of_text;
    assert_eq!(kind_of_text(" Secure Note "), Some(ItemKind::Note));
    assert_eq!(kind_of_text("API-Key"), Some(ItemKind::ApiKey));
    assert_eq!(kind_of_text("card"), None);
}
