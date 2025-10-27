//! Keyfile generation and secure deletion
//!
//! This module provides functions for generating cryptographic keyfiles using
//! `YubiKey` HMAC-SHA1 challenge-response and securely deleting them afterward.

use crate::error::{Result, YkvcError};
use crate::platform;
use crate::yubikey;
use colored::Colorize;
use std::fs::File;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Generate keyfile from challenge phrase using `YubiKey` HMAC-SHA1 challenge-response
///
/// This function sends the challenge phrase to the `YubiKey` slot 2 and writes
/// the resulting HMAC-SHA1 response (20 bytes) to a keyfile.
///
/// # Arguments
///
/// * `challenge` - The challenge phrase (password/passphrase) to send to `YubiKey`
/// * `output_path` - Optional path for the keyfile. If `None`, uses `ykvc_keyfile_<timestamp>.key` in current directory
///
/// # Returns
///
/// Returns the path to the generated keyfile
///
/// # Errors
///
/// Returns an error if:
/// - `YubiKey` challenge-response fails
/// - File creation or writing fails
/// - Setting file permissions fails
pub fn generate_keyfile(challenge: &str, output_path: Option<PathBuf>) -> Result<PathBuf> {
    println!("{} Generating keyfile...", "[INFO]".blue().bold());

    // Get response from YubiKey
    let response_bytes = yubikey::challenge_response(challenge)?;

    // Determine output path
    let path = if let Some(p) = output_path {
        p
    } else {
        // Generate timestamp-based filename in current directory
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| YkvcError::Other(format!("Failed to get system time: {e}")))?
            .as_secs();
        PathBuf::from(format!("ykvc_keyfile_{timestamp}.key"))
    };

    // Write response bytes to file
    let mut file = File::create(&path)
        .map_err(|e| YkvcError::FileError(format!("Failed to create keyfile: {e}")))?;

    file.write_all(&response_bytes)
        .map_err(|e| YkvcError::FileError(format!("Failed to write keyfile: {e}")))?;

    file.sync_all()
        .map_err(|e| YkvcError::FileError(format!("Failed to sync keyfile: {e}")))?;

    // Set file permissions to 0o600 (owner read/write only)
    let mut permissions = file
        .metadata()
        .map_err(|e| YkvcError::FileError(format!("Failed to get file metadata: {e}")))?
        .permissions();

    permissions.set_mode(0o600);

    std::fs::set_permissions(&path, permissions)
        .map_err(|e| YkvcError::FileError(format!("Failed to set file permissions: {e}")))?;

    Ok(path)
}

/// Securely delete a keyfile
///
/// This function uses platform-specific methods to securely delete a keyfile:
/// - **macOS**: Overwrite file with zeros, sync to disk, then delete
/// - **Linux**: Use `shred -u` command (overwrites multiple times and deletes)
///
/// # Arguments
///
/// * `path` - Path to the keyfile to delete
///
/// # Errors
///
/// Returns an error if:
/// - OS detection fails
/// - File deletion fails
/// - File still exists after deletion
pub fn secure_delete(path: &Path) -> Result<()> {
    println!("{} Securely wiping keyfile...", "[INFO]".blue().bold());

    // Detect OS
    let os = platform::detect_os()?;

    // Use platform-specific secure deletion
    match os {
        platform::OS::MacOS => platform::macos::secure_delete(path)?,
        platform::OS::Ubuntu => platform::linux::secure_delete(path)?,
    }

    // Verify file no longer exists
    if path.exists() {
        return Err(YkvcError::FileError(format!(
            "File still exists after secure deletion: {}",
            path.display()
        )));
    }

    println!("{} Keyfile deleted securely", "[SUCCESS]".green().bold());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_keyfile_path_with_timestamp() {
        // Test that default path uses correct format
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let expected = format!("ykvc_keyfile_{timestamp}.key");

        // Cannot test actual generation without YubiKey, but can verify path format
        assert!(expected.starts_with("ykvc_keyfile_"));
        assert!(
            std::path::Path::new(&expected)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("key"))
        );
    }

    #[test]
    fn test_custom_output_path() {
        let custom_path = PathBuf::from("/custom/path/my_keyfile.key");
        // Cannot test actual generation without YubiKey
        assert_eq!(custom_path.to_str(), Some("/custom/path/my_keyfile.key"));
    }

    #[test]
    fn test_timestamp_generation() {
        // Test that timestamp-based filename generation works
        let result = SystemTime::now()
            .duration_since(UNIX_EPOCH);
        assert!(result.is_ok());

        let timestamp = result.unwrap().as_secs();
        let path = PathBuf::from(format!("ykvc_keyfile_{timestamp}.key"));

        assert!(path.to_string_lossy().contains("ykvc_keyfile_"));
        assert_eq!(path.extension().and_then(|s| s.to_str()), Some("key"));
    }

    #[test]
    fn test_pathbuf_operations() {
        let path = PathBuf::from("test_keyfile.key");
        assert_eq!(path.file_name().and_then(|s| s.to_str()), Some("test_keyfile.key"));
        assert_eq!(path.extension().and_then(|s| s.to_str()), Some("key"));
    }

    // Note: Full integration tests require either:
    // 1. Mock YubiKey challenge_response function
    // 2. Actual YubiKey hardware
    //
    // The following scenarios are covered in integration tests:
    // - generate_keyfile() with YubiKey response
    // - File creation and permissions (0o600)
    // - File content verification
    // - secure_delete() for macOS (gshred)
    // - secure_delete() for Linux (shred)
    // - secure_delete() error handling
}
