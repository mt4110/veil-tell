use super::*;
use std::os::unix::{fs::symlink, net::UnixListener};

#[test]
fn reports_only_fixed_labels_without_paths_arguments_or_repeated_codes() -> Result<()> {
    let home = tempfile::tempdir()?;
    let project = tempfile::tempdir()?;
    let npm = home.path().join(".npm/_logs");
    fs::create_dir_all(&npm)?;
    fs::write(npm.join("credential-in-filename.log"),
        b"14 error code ENOENT\n15 error syscall open\n17 error errno -2\n18 error enoent ENOENT: open '/private/company'\n19 verbose argv install EACCES\n19 error syscall open private-data\n20 error syscall secret-operation\n--password sensitive ?token=secret Authorization: Bearer secret 1234567890abcdefghijklmnopqrstuvwxyzABCD \xff\n")?;
    fs::write(
        home.path().join(".pnpm-debug.log"),
        br#"{ "code": "ERR_PNPM_OUTDATED_LOCKFILE", "path": "/private/company" }"#,
    )?;
    fs::write(
        home.path().join("yarn-error.log"),
        "➤ YN0028: private text\nYN0028\nX_YN0009 YN0018_SUFFIX\n",
    )?;

    let path = diagnostics(home.path(), project.path())?.unwrap();
    assert!(path.starts_with(project.path().join(".veil-tell/logs")));
    assert_eq!(path.metadata()?.mode() & 0o777, 0o600);
    assert_eq!(path.parent().unwrap().metadata()?.mode() & 0o777, 0o700);
    assert_eq!(
        fs::read_to_string(path)?,
        concat!(
            "Manager diagnostics (recognized entries from temporary logs)\n",
            "[npm]\nENOENT - file or directory missing\nsyscall: open\n",
            "[pnpm]\nERR_PNPM_OUTDATED_LOCKFILE - lockfile needs updating\n",
            "[yarn]\nYN0028 - installation would change the lockfile\n"
        )
    );
    Ok(())
}

#[test]
fn bounded_scan_finds_the_error_at_the_end_and_marks_omissions() -> Result<()> {
    let home = tempfile::tempdir()?;
    let project = tempfile::tempdir()?;
    let dir = home.path().join(".npm/_logs");
    fs::create_dir_all(&dir)?;
    fs::write(dir.join("01.log"), "1 error code EACCES\n")?;
    let mut latest = fs::File::create(dir.join("02.log"))?;
    writeln!(latest, "1 error code EINTEGRITY")?;
    latest.set_len(DIAGNOSTIC_LIMIT + 100)?;
    latest.seek(SeekFrom::End(0))?;
    writeln!(latest, "\n15 error code EAI_AGAIN")?;
    let report = fs::read_to_string(diagnostics(home.path(), project.path())?.unwrap())?;
    assert!(report.contains("EAI_AGAIN - temporary name resolution failure"));
    assert!(report.contains("Scan limited to 1 MiB across logs."));
    assert!(!report.contains("EACCES") && !report.contains("EINTEGRITY"));
    assert!(report.len() < 1024);
    Ok(())
}

#[test]
fn logs_with_unknown_errors_get_an_explicit_summary() -> Result<()> {
    let home = tempfile::tempdir()?;
    let project = tempfile::tempdir()?;
    assert!(diagnostics(home.path(), project.path())?.is_none());
    fs::write(
        home.path().join("pnpm-debug.log"),
        "ERR_PNPM_PRIVATE_ORGANIZATION\n",
    )?;
    let report = fs::read_to_string(diagnostics(home.path(), project.path())?.unwrap())?;
    assert!(report.ends_with("[pnpm]\nNo recognized diagnostic entry in the scanned data.\n"));
    Ok(())
}

#[test]
fn skips_linked_logs_and_special_files_and_rejects_a_linked_destination() -> Result<()> {
    let home = tempfile::tempdir()?;
    let project = tempfile::tempdir()?;
    let external = tempfile::tempdir()?;
    let secret = external.path().join("outside.log");
    fs::write(&secret, "EACCES")?;
    let npm = home.path().join(".npm/_logs");
    fs::create_dir_all(&npm)?;
    symlink(&secret, npm.join("file.log"))?;
    fs::hard_link(&secret, npm.join("linked.log"))?;
    let _socket = UnixListener::bind(npm.join("socket.log"))?;
    let yarn = home.path().join(".yarn");
    fs::create_dir(&yarn)?;
    symlink(external.path(), yarn.join("_logs"))?;
    assert!(diagnostics(home.path(), project.path())?.is_none());

    let state = project.path().join(".veil-tell");
    fs::create_dir(&state)?;
    symlink(external.path(), state.join("logs"))?;
    fs::write(npm.join("regular.log"), "ENOENT")?;
    assert!(diagnostics(home.path(), project.path()).is_err());
    assert_eq!(fs::read_dir(external.path())?.count(), 1);
    Ok(())
}
