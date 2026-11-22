//! Architecture Guard tests enforcing Clean Architecture boundaries,
//! file size limits (< 850 lines per file), and zero Python scripts.

use std::fs;
use std::path::{Path, PathBuf};

const MAX_LINES_PER_RUST_FILE: usize = 850;

fn collect_files(dir: &Path, ext: &str, out: &mut Vec<PathBuf>) {
    if !dir.is_dir() {
        return;
    }
    for entry in fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        let name = entry.file_name();
        if matches!(name.to_str(), Some(".git" | "target")) {
            continue;
        }
        if entry.file_type().unwrap().is_dir() {
            collect_files(&path, ext, out);
        } else if path.extension().and_then(|s| s.to_str()) == Some(ext) {
            out.push(path);
        }
    }
}

#[test]
fn root_src_only_contains_entrypoints_and_four_layers() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let src_dir = root.join("src");
    let mut allowed_files = Vec::new();
    let mut allowed_dirs = Vec::new();
    for entry in fs::read_dir(&src_dir).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().into_string().unwrap();
        if entry.file_type().unwrap().is_dir() {
            allowed_dirs.push(name);
        } else {
            allowed_files.push(name);
        }
    }
    allowed_files.sort();
    allowed_dirs.sort();
    assert_eq!(
        allowed_files,
        vec!["lib.rs", "main.rs"],
        "src/ root must only contain lib.rs and main.rs"
    );
    assert_eq!(
        allowed_dirs,
        vec!["application", "domain", "infrastructure", "interface"],
        "src/ root must only contain the four Clean Architecture layer directories"
    );
}

#[test]
fn domain_layer_does_not_depend_on_outer_layers() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let domain_dir = root.join("src/domain");
    let mut files = Vec::new();
    collect_files(&domain_dir, "rs", &mut files);

    let forbidden = [
        "crate::application",
        "crate::infrastructure",
        "crate::interface",
        "crate::agent",
        "crate::rollup",
        "crate::session",
        "crate::verify",
        "crate::attribution",
        "crate::cargo_attribution",
        "crate::isolation",
        "crate::manager_files",
        "crate::pnpm",
        "crate::proxy",
        "crate::upstream",
        "crate::cli",
        "crate::summary",
        "crate::dispatch",
    ];

    for file in files {
        let content = fs::read_to_string(&file).unwrap();
        for token in forbidden {
            assert!(
                !content.contains(token),
                "Clean Architecture violation: domain file {} depends on outer layer symbol `{token}`",
                file.display()
            );
        }
    }
}

#[test]
fn application_layer_does_not_depend_on_interface_layer() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let app_dir = root.join("src/application");
    let mut files = Vec::new();
    collect_files(&app_dir, "rs", &mut files);

    let forbidden = [
        "crate::interface",
        "crate::cli",
        "crate::summary",
        "crate::dispatch",
    ];

    for file in files {
        let content = fs::read_to_string(&file).unwrap();
        for token in forbidden {
            assert!(
                !content.contains(token),
                "Clean Architecture violation: application file {} depends on interface layer symbol `{token}`",
                file.display()
            );
        }
    }
}

#[test]
fn no_rust_file_exceeds_line_limit() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut rust_files = Vec::new();
    collect_files(&root.join("src"), "rs", &mut rust_files);
    collect_files(&root.join("examples"), "rs", &mut rust_files);

    for file in rust_files {
        let count = fs::read_to_string(&file).unwrap().lines().count();
        assert!(
            count <= MAX_LINES_PER_RUST_FILE,
            "Architecture guard: {} has {count} lines (limit is {MAX_LINES_PER_RUST_FILE}; split responsibilities before approaching 1000 lines)",
            file.strip_prefix(root).unwrap().display()
        );
    }
}

#[test]
fn repository_contains_zero_python_files() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut py_files = Vec::new();
    collect_files(root, "py", &mut py_files);
    assert!(
        py_files.is_empty(),
        "Architecture guard: repository must not contain Python files, found: {py_files:?}"
    );
}
