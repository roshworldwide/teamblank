// SENTINELWIPE desktop shell.
//
// This binary carries no logic on purpose. It is a native window around the two
// self-contained pages the engine's pipeline produces (`make ui`), bundled at
// compile time so the app runs on an air-gapped machine with nothing installed.
// It uses the platform's own webview — no Chromium bundle — which is why the
// binary is measured in megabytes, not hundreds of them.
//
// The shell never links the engine and exposes no IPC: the capability set is
// empty, and the CSP in tauri.conf.json refuses every network destination. A
// page that cannot phone home from inside the demo binary is a property worth
// having, not an accident.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    tauri::Builder::default()
        .run(tauri::generate_context!())
        .expect("SENTINELWIPE shell failed to start");
}
