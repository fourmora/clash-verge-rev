use crate::core::{
    notification::{self, PendingFailure},
    runstate::{RUN_STATE, RunStateView},
};

/// Returns one coherent core/service snapshot instead of independently refreshed state.
#[tauri::command]
#[specta::specta]
pub async fn get_runtime_state() -> Result<RunStateView, String> {
    Ok(RUN_STATE.settled().await.to_view())
}

#[tauri::command]
#[specta::specta]
pub async fn get_pending_failures() -> Vec<PendingFailure> {
    notification::pending_failures()
}

/// Lists running process names for the per-app proxy picker.
#[tauri::command]
#[specta::specta]
pub async fn list_system_processes() -> Vec<std::string::String> {
    tauri::async_runtime::spawn_blocking(crate::utils::process_list::list_process_names)
        .await
        .unwrap_or_default()
}
