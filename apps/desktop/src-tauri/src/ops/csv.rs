//! CSV import and export (T23). The file path comes from the webview, so it is checked first
//! (`files`). The bytes of an import file are read here, handed to the core and zeroized when the
//! call ends. Nothing is logged: not a path, not a row, not a value.

use std::io::Read;

use cerberus_core::csvio::{self, ImportOptions, MAX_FILE_BYTES};
use cerberus_types::OperatorRole as CoreRole;
use cerberus_types::WorkspaceId;
use zeroize::Zeroizing;

use super::files;
use crate::dto::{CsvImportRequest, ImportPreviewView, ImportReport};
use crate::error::{IpcError, IpcResult};
use crate::guard::check;
use crate::state::DesktopState;

fn read_import_file(state: &DesktopState, path: &str) -> IpcResult<Zeroizing<Vec<u8>>> {
    let max = u64::try_from(MAX_FILE_BYTES).unwrap_or(u64::MAX);
    let path = files::picked_file(state, "path", path, max)?;
    let file = std::fs::File::open(path)?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(
        usize::try_from(file.metadata()?.len())
            .unwrap_or(0)
            .min(MAX_FILE_BYTES)
            + 1,
    ));
    // One byte over the limit tells a file that grew after the size check.
    file.take(max + 1).read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn options(request: CsvImportRequest) -> IpcResult<(String, ImportOptions)> {
    let workspace_id: WorkspaceId = crate::dto::id("workspace_id", &request.workspace_id)?;
    let mut mapping = std::collections::BTreeMap::new();
    for (field, column) in request.mapping.columns {
        let known = csvio::Field::from_name(&field)
            .ok_or_else(|| IpcError::invalid("mapping", "names a field that does not exist"))?;
        mapping.insert(known, column);
    }
    let role_label = request
        .role_label
        .map(|r| r.trim().to_owned())
        .filter(|r| !r.is_empty());
    Ok((
        request.path,
        ImportOptions {
            source: request.source.into(),
            workspace_id,
            environment: request.environment.into(),
            role_label,
            mapping,
            duplicates: request.duplicates.into(),
        },
    ))
}

/// `csv_preview`: operator. Reads the file and says what an import would do. Writes nothing.
pub async fn csv_preview(
    state: &DesktopState,
    window: &str,
    request: CsvImportRequest,
) -> IpcResult<ImportPreviewView> {
    check(window, "csv_preview")?;
    let (core, ctx) = state.operator().await?;
    core.authorize_role(&ctx, CoreRole::Operator).await?;
    let (path, options) = options(request)?;
    let bytes = read_import_file(state, &path)?;
    Ok(core.csv_preview(&ctx, &bytes, &options).await?.into())
}

/// `csv_import`: operator. Makes all the importable rows as items in one transaction.
pub async fn csv_import(
    state: &DesktopState,
    window: &str,
    request: CsvImportRequest,
) -> IpcResult<ImportReport> {
    check(window, "csv_import")?;
    let (core, ctx) = state.operator().await?;
    core.authorize_role(&ctx, CoreRole::Operator).await?;
    let (path, options) = options(request)?;
    let bytes = read_import_file(state, &path)?;
    Ok(core.csv_import(&ctx, &bytes, &options).await?.into())
}

/// `csv_export`: owner. Writes a new file, mode 0600, with every secret in plain text. Returns
/// the number of items.
pub async fn csv_export(
    state: &DesktopState,
    window: &str,
    dest: String,
    workspace_id: Option<String>,
) -> IpcResult<u64> {
    check(window, "csv_export")?;
    let (core, ctx) = state.operator().await?;
    core.authorize_role(&ctx, CoreRole::Owner).await?;
    let dest = files::new_file("dest", &dest)?;
    let workspace = crate::dto::opt_id::<WorkspaceId>("workspace_id", workspace_id.as_deref())?;
    let export = core.csv_export(&ctx, workspace).await?;
    if let Err(error) = files::write_new_private(&dest, &export.bytes) {
        if error.code != "conflict" {
            // A half-written plain-text file must not stay behind.
            let _ = std::fs::remove_file(&dest);
        }
        return Err(error);
    }
    Ok(export.count)
}
