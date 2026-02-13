#![cfg(unix)]

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::Duration,
};

use gloves::vault::gocryptfs::{FsEncryptionDriver, GocryptfsDriver, InitRequest, MountRequest};

fn write_script(path: &Path, body: &str) {
    fs::write(path, body).unwrap();
    let mut permissions = fs::metadata(path).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).unwrap();
}

fn build_driver(bin_dir: &Path) -> GocryptfsDriver {
    GocryptfsDriver::with_binaries(
        bin_dir.join("gocryptfs").to_string_lossy().to_string(),
        bin_dir.join("fusermount").to_string_lossy().to_string(),
        bin_dir.join("mountpoint").to_string_lossy().to_string(),
    )
}

fn wait_for(predicate: impl Fn() -> bool) -> bool {
    for _ in 0..500 {
        if predicate() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    false
}

#[test]
fn init_creates_cipher_dir() {
    let temp_dir = tempfile::tempdir().unwrap();
    let bin_dir = temp_dir.path().join("bin");
    let logs_dir = temp_dir.path().join("logs");
    fs::create_dir_all(&bin_dir).unwrap();
    fs::create_dir_all(&logs_dir).unwrap();

    let args_log = logs_dir.join("gocryptfs.log");
    let gocryptfs_script = r#"#!/usr/bin/env bash
set -euo pipefail
echo "$*" >> "__LOG__"
if [[ "$1" == "-init" ]]; then
  cipher=""
  for arg in "$@"; do
    cipher="$arg"
  done
  mkdir -p "$cipher"
  touch "$cipher/gocryptfs.conf"
fi
"#;
    write_script(
        &bin_dir.join("gocryptfs"),
        &gocryptfs_script.replace("__LOG__", &args_log.to_string_lossy()),
    );
    write_script(
        &bin_dir.join("fusermount"),
        &r#"#!/usr/bin/env bash
set -euo pipefail
echo "$*" >> "__LOG__"
"#
        .replace(
            "__LOG__",
            &logs_dir.join("fusermount.log").to_string_lossy(),
        ),
    );
    write_script(
        &bin_dir.join("mountpoint"),
        r#"#!/usr/bin/env bash
set -euo pipefail
if [[ "$1" != "-q" ]]; then
  exit 2
fi
if [[ -f "$2/.mounted" ]]; then
  exit 0
fi
exit 1
"#,
    );

    let driver = build_driver(&bin_dir);

    let cipher_dir = temp_dir.path().join("cipher");
    driver
        .init(&InitRequest {
            cipher_dir: cipher_dir.clone(),
            extpass_command: "gloves --root /tmp get vault/agent_data".to_owned(),
        })
        .unwrap();

    assert!(cipher_dir.exists());
    assert!(cipher_dir.join("gocryptfs.conf").exists());
    assert!(wait_for(|| args_log.exists()));
    let log = fs::read_to_string(args_log).unwrap();
    assert!(log.contains("-init"));
    assert!(log.contains("-extpass"));
}

#[test]
fn mount_passes_extpass_and_idle() {
    let temp_dir = tempfile::tempdir().unwrap();
    let bin_dir = temp_dir.path().join("bin");
    let logs_dir = temp_dir.path().join("logs");
    fs::create_dir_all(&bin_dir).unwrap();
    fs::create_dir_all(&logs_dir).unwrap();

    let args_log = logs_dir.join("gocryptfs.log");
    let gocryptfs_script = r#"#!/usr/bin/env bash
set -euo pipefail
echo "$*" >> "__LOG__"
if [[ "$1" == "-init" ]]; then
  exit 0
fi
mount_point=""
for arg in "$@"; do
  mount_point="$arg"
done
"#;
    write_script(
        &bin_dir.join("gocryptfs"),
        &gocryptfs_script.replace("__LOG__", &args_log.to_string_lossy()),
    );
    write_script(
        &bin_dir.join("fusermount"),
        &r#"#!/usr/bin/env bash
set -euo pipefail
echo "$*" >> "__LOG__"
if [[ "$1" == "-u" ]]; then
  rm -f "$2/.mounted"
fi
"#
        .replace(
            "__LOG__",
            &logs_dir.join("fusermount.log").to_string_lossy(),
        ),
    );
    write_script(
        &bin_dir.join("mountpoint"),
        r#"#!/usr/bin/env bash
set -euo pipefail
if [[ "$1" != "-q" ]]; then
  exit 2
fi
if [[ -f "$2/.mounted" ]]; then
  exit 0
fi
exit 1
"#,
    );

    let driver = build_driver(&bin_dir);

    let mount_point = temp_dir.path().join("mount");
    driver
        .mount(&MountRequest {
            cipher_dir: temp_dir.path().join("cipher"),
            mount_point: mount_point.clone(),
            extpass_command: "gloves --root /tmp get vault/agent_data".to_owned(),
            idle_timeout: Some(Duration::from_secs(3600)),
        })
        .unwrap();

    assert!(wait_for(|| args_log.exists()));
    let log = fs::read_to_string(args_log).unwrap();
    assert!(log.contains("-idle 3600s"));
    assert!(log.contains("gloves --root /tmp get vault/agent_data"));
}

#[test]
fn unmount_calls_fusermount() {
    let temp_dir = tempfile::tempdir().unwrap();
    let bin_dir = temp_dir.path().join("bin");
    let logs_dir = temp_dir.path().join("logs");
    fs::create_dir_all(&bin_dir).unwrap();
    fs::create_dir_all(&logs_dir).unwrap();

    let gocryptfs_log = logs_dir.join("gocryptfs.log");
    let gocryptfs_script = r#"#!/usr/bin/env bash
set -euo pipefail
echo "$*" >> "__LOG__"
mount_point=""
for arg in "$@"; do
  mount_point="$arg"
done
"#;
    write_script(
        &bin_dir.join("gocryptfs"),
        &gocryptfs_script.replace("__LOG__", &gocryptfs_log.to_string_lossy()),
    );
    let fuser_log = logs_dir.join("fusermount.log");
    write_script(
        &bin_dir.join("fusermount"),
        &r#"#!/usr/bin/env bash
set -euo pipefail
echo "$*" >> "__LOG__"
if [[ "$1" == "-u" ]]; then
  rm -f "$2/.mounted"
fi
"#
        .replace("__LOG__", &fuser_log.to_string_lossy()),
    );
    write_script(
        &bin_dir.join("mountpoint"),
        r#"#!/usr/bin/env bash
set -euo pipefail
if [[ "$1" != "-q" ]]; then
  exit 2
fi
if [[ -f "$2/.mounted" ]]; then
  exit 0
fi
exit 1
"#,
    );

    let driver = build_driver(&bin_dir);

    let mount_point = temp_dir.path().join("mount");
    driver
        .mount(&MountRequest {
            cipher_dir: temp_dir.path().join("cipher"),
            mount_point: mount_point.clone(),
            extpass_command: "gloves --root /tmp get vault/agent_data".to_owned(),
            idle_timeout: None,
        })
        .unwrap();
    assert!(wait_for(|| gocryptfs_log.exists()));
    fs::create_dir_all(&mount_point).unwrap();
    fs::write(mount_point.join(".mounted"), b"mounted").unwrap();
    assert!(driver.is_mounted(&mount_point).unwrap());

    driver.unmount(&mount_point).unwrap();
    assert!(wait_for(|| !mount_point.join(".mounted").exists()));
    assert!(!driver.is_mounted(&mount_point).unwrap());

    let log = fs::read_to_string(fuser_log).unwrap();
    assert!(log.contains("-u"));
    assert!(log.contains(mount_point.to_string_lossy().as_ref()));
}

#[test]
fn is_mounted_false() {
    let temp_dir = tempfile::tempdir().unwrap();
    let bin_dir = temp_dir.path().join("bin");
    fs::create_dir_all(&bin_dir).unwrap();

    write_script(
        &bin_dir.join("gocryptfs"),
        r#"#!/usr/bin/env bash
set -euo pipefail
"#,
    );
    write_script(
        &bin_dir.join("fusermount"),
        r#"#!/usr/bin/env bash
set -euo pipefail
"#,
    );
    write_script(
        &bin_dir.join("mountpoint"),
        r#"#!/usr/bin/env bash
set -euo pipefail
if [[ "$1" != "-q" ]]; then
  exit 2
fi
if [[ -f "$2/.mounted" ]]; then
  exit 0
fi
exit 1
"#,
    );

    let driver = build_driver(&bin_dir);
    assert!(!driver
        .is_mounted(PathBuf::from("/tmp/missing").as_path())
        .unwrap());
}
