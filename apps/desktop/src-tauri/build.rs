//! Build script for the Cerberus desktop shell. It makes the Tauri permission for each IPC command
//! (`allow-<command>`), so a capability file can give each window only the commands it needs.

include!("src/names.rs");

fn main() {
    let attributes = tauri_build::Attributes::new()
        .app_manifest(tauri_build::AppManifest::new().commands(&ALL_COMMANDS));
    if let Err(error) = tauri_build::try_build(attributes) {
        eprintln!("tauri build failed: {error:#}");
        std::process::exit(1);
    }
}
