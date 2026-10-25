use std::collections::BTreeSet;

/// Lists the names of running processes, deduplicated and sorted.
///
/// Used by the per-app proxy picker (Windows / macOS / Linux).
pub fn list_process_names() -> Vec<std::string::String> {
    let mut sys = sysinfo::System::new();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);

    let mut names: BTreeSet<std::string::String> = BTreeSet::new();
    for process in sys.processes().values() {
        let name = process.name().to_string_lossy().trim().to_string();
        if !name.is_empty() {
            names.insert(name);
        }
    }
    names.into_iter().collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn lists_at_least_the_current_process() {
        let names = super::list_process_names();
        assert!(!names.is_empty());
    }
}
