use std::fs;
use std::path::{Path, PathBuf};

fn collect_rs_files(root: &Path, out: &mut Vec<PathBuf>) {
    let entries = match fs::read_dir(root) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, out);
            continue;
        }
        if path.extension().and_then(|s| s.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

pub fn read_objectives_source() -> String {
    // Canonical objective implementations live under `src/tactics/objectives/`.
    // Anchor tests should scan that tree rather than relying on the legacy re-export file.
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let root = repo_root.join("src/tactics/objectives");
    let mut files = Vec::new();
    collect_rs_files(&root, &mut files);
    files.sort();

    let mut out = String::new();
    for file in files {
        if let Ok(content) = fs::read_to_string(&file) {
            out.push_str("\n// --- FILE: ");
            out.push_str(file.to_string_lossy().as_ref());
            out.push_str(" ---\n");
            out.push_str(&content);
        }
    }

    // Include the legacy bridge too (re-export surface).
    let legacy_path = repo_root.join("src/solver/objectives.rs");
    if let Ok(legacy) = fs::read_to_string(&legacy_path) {
        out.push_str("\n// --- FILE: src/solver/objectives.rs ---\n");
        out.push_str(&legacy);
    }

    out
}
