//! Integration tests for platform-specific functionality

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;

#[test]
fn test_file_permissions_creation() {
    // Test creating a file with specific permissions
    let temp_dir = std::env::temp_dir();
    let test_file = temp_dir.join("test_permissions.txt");

    // Create file with default permissions
    let mut file = fs::File::create(&test_file).unwrap();
    file.write_all(b"test data").unwrap();

    // Set permissions to 0o600
    let mut perms = file.metadata().unwrap().permissions();
    perms.set_mode(0o600);
    fs::set_permissions(&test_file, perms).unwrap();

    // Verify permissions
    let metadata = fs::metadata(&test_file).unwrap();
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);

    // Clean up
    fs::remove_file(test_file).unwrap();
}

#[test]
fn test_file_sync_operations() {
    // Test file sync operations used in keyfile generation
    let temp_dir = std::env::temp_dir();
    let test_file = temp_dir.join("test_sync.txt");

    let mut file = fs::File::create(&test_file).unwrap();
    file.write_all(b"test data for sync").unwrap();

    // Test sync_all (flushes to disk)
    let result = file.sync_all();
    assert!(result.is_ok());

    // Clean up
    drop(file);
    fs::remove_file(test_file).unwrap();
}

#[test]
fn test_file_metadata_operations() {
    // Test file metadata operations
    let temp_dir = std::env::temp_dir();
    let test_file = temp_dir.join("test_metadata.txt");

    let mut file = fs::File::create(&test_file).unwrap();
    file.write_all(b"test data").unwrap();

    // Get metadata
    let metadata = file.metadata().unwrap();
    assert!(metadata.is_file());
    assert_eq!(metadata.len(), 9); // "test data" is 9 bytes

    // Clean up
    drop(file);
    fs::remove_file(test_file).unwrap();
}

#[test]
fn test_path_operations() {
    use std::path::PathBuf;

    // Test various path operations
    let path = PathBuf::from("/tmp/test/keyfile.key");

    assert_eq!(path.file_name().and_then(|s| s.to_str()), Some("keyfile.key"));
    assert_eq!(path.extension().and_then(|s| s.to_str()), Some("key"));
    assert_eq!(path.parent().and_then(|p| p.to_str()), Some("/tmp/test"));

    // Test path display
    let display = format!("{}", path.display());
    assert_eq!(display, "/tmp/test/keyfile.key");
}

#[test]
fn test_temp_file_creation_and_deletion() {
    // Test temporary file operations
    use tempfile::NamedTempFile;

    let temp_file = NamedTempFile::new().unwrap();
    let path = temp_file.path().to_path_buf();

    // File should exist
    assert!(path.exists());

    // Write data
    let mut file = fs::OpenOptions::new().write(true).open(&path).unwrap();
    file.write_all(b"temporary data").unwrap();
    drop(file);

    // Read data back
    let content = fs::read_to_string(&path).unwrap();
    assert_eq!(content, "temporary data");

    // File is automatically deleted when NamedTempFile is dropped
}

#[test]
fn test_command_execution_wrapper() {
    use std::process::Command;

    // Test that we can execute commands and check results
    let output = Command::new("echo").arg("test").output().unwrap();

    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "test");
}

#[test]
fn test_error_message_formatting() {
    // Test error message formatting used throughout the codebase
    let path = std::path::Path::new("/test/file.key");
    let error_msg = format!("File does not exist: {}", path.display());
    assert!(error_msg.contains("/test/file.key"));
}

#[test]
#[cfg(target_os = "macos")]
fn test_macos_specific_commands() {
    use std::process::Command;

    // Test that command -v works on macOS
    let output = Command::new("sh").arg("-c").arg("command -v sh").output().unwrap();
    assert!(output.status.success());
}

#[test]
#[cfg(target_os = "linux")]
fn test_linux_specific_commands() {
    use std::process::Command;

    // Test that command -v works on Linux
    let output = Command::new("sh").arg("-c").arg("command -v sh").output().unwrap();
    assert!(output.status.success());
}
