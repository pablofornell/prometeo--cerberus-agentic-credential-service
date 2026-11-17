//! Cerberus desktop shell entry point. The app is in the `cerberus_desktop` library.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    cerberus_desktop::run();
}
