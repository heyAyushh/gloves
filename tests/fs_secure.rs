use gloves::fs_secure::{
    create_private_file_if_missing, ensure_private_dir, write_private_file_atomic,
};

#[test]
fn create_private_file_if_missing_does_not_overwrite() {
    let temp_dir = tempfile::tempdir().unwrap();
    let file_path = temp_dir.path().join("data.bin");

    create_private_file_if_missing(&file_path, b"one").unwrap();
    create_private_file_if_missing(&file_path, b"two").unwrap();

    assert_eq!(std::fs::read(&file_path).unwrap(), b"one");
}

#[test]
fn write_private_file_atomic_overwrites() {
    let temp_dir = tempfile::tempdir().unwrap();
    let file_path = temp_dir.path().join("data.bin");

    write_private_file_atomic(&file_path, b"one").unwrap();
    write_private_file_atomic(&file_path, b"two").unwrap();

    assert_eq!(std::fs::read(&file_path).unwrap(), b"two");
}

#[test]
fn ensure_private_dir_creates_directory() {
    let temp_dir = tempfile::tempdir().unwrap();
    let dir_path = temp_dir.path().join("nested/private");

    ensure_private_dir(&dir_path).unwrap();

    assert!(dir_path.exists());
    assert!(dir_path.is_dir());
}

#[cfg(unix)]
#[test]
fn private_permissions_are_restricted() {
    use std::os::unix::fs::PermissionsExt;

    let temp_dir = tempfile::tempdir().unwrap();
    let dir_path = temp_dir.path().join("private_dir");
    let file_path = dir_path.join("file.bin");

    ensure_private_dir(&dir_path).unwrap();
    write_private_file_atomic(&file_path, b"secret").unwrap();

    let dir_mode = std::fs::metadata(&dir_path).unwrap().permissions().mode() & 0o777;
    let file_mode = std::fs::metadata(&file_path).unwrap().permissions().mode() & 0o777;

    assert_eq!(dir_mode, 0o700);
    assert_eq!(file_mode, 0o600);
}
