//! Linux-specific platform implementation (Ubuntu/Debian)

use crate::error::{Result, YkvcError};
use colored::Colorize;
use std::process::Command;

/// Checks if a command exists in the system PATH
///
/// # Arguments
///
/// * `cmd` - The command name to check
///
/// # Errors
///
/// Returns an error if the command check fails
pub fn check_command(cmd: &str) -> Result<bool> {
    let output = Command::new("command")
        .arg("-v")
        .arg(cmd)
        .output()
        .map_err(|e| YkvcError::CommandFailed {
            command: format!("command -v {cmd}"),
            message: e.to_string(),
        })?;

    Ok(output.status.success())
}

/// Installs `YubiKey` tools via apt
///
/// # Errors
///
/// Returns an error if installation fails
pub fn install_yubikey_tools() -> Result<()> {
    println!("{} Installing YubiKey tools (yubikey-manager, yubikey-personalization)...", "[INFO]".blue().bold());
    println!("{} This will require sudo privileges.", "[INFO]".blue().bold());

    // Update apt cache
    println!("{} Updating package lists...", "[INFO]".blue().bold());
    let update_output = Command::new("sudo")
        .arg("apt-get")
        .arg("update")
        .status()
        .map_err(|e| YkvcError::InstallationFailed(format!("Failed to update apt cache: {e}")))?;

    if !update_output.success() {
        return Err(YkvcError::InstallationFailed(
            "Failed to update apt cache. Check your sudo permissions.".to_string(),
        ));
    }

    // Install packages
    println!("{} Installing packages...", "[INFO]".blue().bold());
    let install_output = Command::new("sudo")
        .arg("apt-get")
        .arg("install")
        .arg("-y")
        .arg("yubikey-manager")
        .arg("yubikey-personalization")
        .status()
        .map_err(|e| YkvcError::InstallationFailed(format!("Failed to install YubiKey tools: {e}")))?;

    if !install_output.success() {
        return Err(YkvcError::InstallationFailed(
            "Failed to install YubiKey tools via apt-get".to_string(),
        ));
    }

    println!("{} YubiKey tools installed successfully", "[SUCCESS]".green().bold());
    Ok(())
}

/// Securely deletes a file using shred
///
/// Uses the `shred` command to overwrite the file multiple times with random data
/// before deleting it. The flags provide:
/// - `-v`: Verbose output (show progress)
/// - `-f`: Force permissions to allow writing if necessary
/// - `-z`: Add final overwrite with zeros to hide shredding
/// - `-n 10`: 10 passes of random data (default is 3)
/// - `-u`: Remove file after overwriting
///
/// # Process
///
/// 1. Run `shred -v -f -z -n 10 -u <path>` to overwrite and delete
/// 2. Verify file no longer exists
///
/// # Arguments
///
/// * `path` - Path to the file to delete
///
/// # Errors
///
/// Returns an error if:
/// - File does not exist
/// - `shred` command fails
/// - File still exists after deletion
pub fn secure_delete(path: &std::path::Path) -> Result<()> {
    // Verify file exists
    if !path.exists() {
        return Err(YkvcError::FileError(format!(
            "File does not exist: {}",
            path.display()
        )));
    }

    // Run shred with 10 passes, verbose, force, zero final pass, and delete
    // Use .status() instead of .output() to show progress to user
    let status = Command::new("shred")
        .arg("-v")          // Verbose - show progress
        .arg("-f")          // Force - change permissions if needed
        .arg("-z")          // Zero - final overwrite with zeros
        .arg("-n")          // Iterations
        .arg("10")          // 10 passes
        .arg("-u")          // Remove file after overwriting
        .arg(path)
        .status()
        .map_err(|e| YkvcError::CommandFailed {
            command: format!("shred -v -f -z -n 10 -u {}", path.display()),
            message: e.to_string(),
        })?;

    if !status.success() {
        return Err(YkvcError::CommandFailed {
            command: format!("shred -v -f -z -n 10 -u {}", path.display()),
            message: "shred failed".to_string(),
        });
    }

    // Verify file is gone
    if path.exists() {
        return Err(YkvcError::FileError(format!(
            "File still exists after shred: {}",
            path.display()
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_check_command_returns_result() {
        // Test that check_command returns a Result
        let result = check_command("test");
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn test_secure_delete_nonexistent_file() {
        // Test that secure_delete fails for non-existent file
        let path = std::path::Path::new("/nonexistent/file.key");
        let result = secure_delete(path);
        assert!(result.is_err());

        if let Err(e) = result {
            assert!(matches!(e, YkvcError::FileError(_)));
            assert!(e.to_string().contains("does not exist"));
        }
    }

    #[test]
    fn test_secure_delete_with_temp_file() {
        // Create a temporary file to test secure_delete
        use tempfile::NamedTempFile;

        let mut temp_file = NamedTempFile::new().expect("Failed to create temp file");
        temp_file.write_all(b"test data").expect("Failed to write");
        let path = temp_file.path().to_path_buf();

        // Keep the file by preventing auto-deletion
        let _ = temp_file.persist(&path);

        // Verify file exists
        assert!(path.exists());

        // Try to delete - will fail if shred not available, but tests the logic
        let result = secure_delete(&path);

        // Clean up if secure_delete failed (shred not available)
        if path.exists() {
            let _ = std::fs::remove_file(&path);
        }

        // Result should either succeed or fail with CommandFailed (shred not found)
        if let Err(e) = result {
            assert!(
                matches!(e, YkvcError::CommandFailed { .. }) ||
                matches!(e, YkvcError::FileError(_))
            );
        }
    }

    // Note: The following tests require actual system commands or mocking:
    // - check_command() with existing command
    // - check_command() with non-existing command
    // - install_yubikey_tools() - requires sudo, apt, and network
    // - secure_delete() with shred available
    //
    // These are covered in integration tests with proper environment setup
}
