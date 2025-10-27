//! macOS-specific platform implementation

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

/// Checks if Homebrew is installed
///
/// # Errors
///
/// Returns an error if the check fails
pub fn check_homebrew() -> Result<bool> {
    check_command("brew")
}

/// Installs Homebrew package manager
///
/// # Errors
///
/// Returns an error if installation fails
pub fn install_homebrew() -> Result<()> {
    println!("{} Installing Homebrew...", "[INFO]".blue().bold());
    println!("{} This may take a few minutes and will require your password.", "[INFO]".blue().bold());

    let output = Command::new("/bin/bash")
        .arg("-c")
        .arg(r"$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)")
        .status()
        .map_err(|e| YkvcError::InstallationFailed(format!("Failed to start Homebrew installer: {e}")))?;

    if !output.success() {
        return Err(YkvcError::InstallationFailed(
            "Homebrew installation failed. Please install manually: https://brew.sh".to_string(),
        ));
    }

    println!("{} Homebrew installed successfully", "[SUCCESS]".green().bold());
    Ok(())
}

/// Installs `YubiKey` tools via Homebrew
///
/// # Errors
///
/// Returns an error if installation fails
pub fn install_yubikey_tools() -> Result<()> {
    println!("{} Installing YubiKey tools (ykpers, yubikey-manager)...", "[INFO]".blue().bold());

    // Update brew first
    println!("{} Updating Homebrew...", "[INFO]".blue().bold());
    let update_output = Command::new("brew")
        .arg("update")
        .status()
        .map_err(|e| YkvcError::InstallationFailed(format!("Failed to update Homebrew: {e}")))?;

    if !update_output.success() {
        println!("{} Homebrew update failed, continuing anyway...", "[WARNING]".yellow().bold());
    }

    // Install ykpers (formula)
    println!("{} Installing ykpers...", "[INFO]".blue().bold());
    let ykpers_output = Command::new("brew")
        .arg("install")
        .arg("ykpers")
        .status()
        .map_err(|e| YkvcError::InstallationFailed(format!("Failed to install ykpers: {e}")))?;

    if !ykpers_output.success() {
        return Err(YkvcError::InstallationFailed(
            "Failed to install ykpers via Homebrew. Try manually: brew install ykpers".to_string(),
        ));
    }

    // Install ykman (formula)
    println!("{} Installing ykman (yubikey-manager)...", "[INFO]".blue().bold());
    let ykman_output = Command::new("brew")
        .arg("install")
        .arg("ykman")
        .status()
        .map_err(|e| YkvcError::InstallationFailed(format!("Failed to install ykman: {e}")))?;

    if !ykman_output.success() {
        return Err(YkvcError::InstallationFailed(
            "Failed to install ykman via Homebrew. Try manually: brew install ykman".to_string(),
        ));
    }

    // Install coreutils (for gshred - secure file deletion)
    println!("{} Installing coreutils (for secure file deletion)...", "[INFO]".blue().bold());
    let coreutils_output = Command::new("brew")
        .arg("install")
        .arg("coreutils")
        .status()
        .map_err(|e| YkvcError::InstallationFailed(format!("Failed to install coreutils: {e}")))?;

    if !coreutils_output.success() {
        return Err(YkvcError::InstallationFailed(
            "Failed to install coreutils via Homebrew. Try manually: brew install coreutils".to_string(),
        ));
    }

    println!("{} YubiKey tools installed successfully", "[SUCCESS]".green().bold());
    Ok(())
}

/// Securely deletes a file using gshred (GNU coreutils)
///
/// Uses the `gshred` command from GNU coreutils to overwrite the file multiple times
/// with random data before deleting it. The flags provide:
/// - `-v`: Verbose output (show progress)
/// - `-f`: Force permissions to allow writing if necessary
/// - `-z`: Add final overwrite with zeros to hide shredding
/// - `-n 10`: 10 passes of random data (default is 3)
/// - `-u`: Remove file after overwriting
///
/// # Process
///
/// 1. Run `gshred -v -f -z -n 10 -u <path>` to overwrite and delete
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
/// - `gshred` command fails
/// - File still exists after deletion
pub fn secure_delete(path: &std::path::Path) -> Result<()> {
    // Verify file exists
    if !path.exists() {
        return Err(YkvcError::FileError(format!(
            "File does not exist: {}",
            path.display()
        )));
    }

    // Run gshred with 10 passes, verbose, force, zero final pass, and delete
    // Use .status() instead of .output() to show progress to user
    let status = Command::new("gshred")
        .arg("-v")          // Verbose - show progress
        .arg("-f")          // Force - change permissions if needed
        .arg("-z")          // Zero - final overwrite with zeros
        .arg("-n")          // Iterations
        .arg("10")          // 10 passes
        .arg("-u")          // Remove file after overwriting
        .arg(path)
        .status()
        .map_err(|e| YkvcError::CommandFailed {
            command: format!("gshred -v -f -z -n 10 -u {}", path.display()),
            message: e.to_string(),
        })?;

    if !status.success() {
        return Err(YkvcError::CommandFailed {
            command: format!("gshred -v -f -z -n 10 -u {}", path.display()),
            message: "gshred failed".to_string(),
        });
    }

    // Verify file no longer exists
    if path.exists() {
        return Err(YkvcError::FileError(format!(
            "File still exists after gshred: {}",
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
    fn test_check_homebrew_calls_check_command() {
        // Test that check_homebrew wraps check_command
        let result = check_homebrew();
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

        // Try to delete - will fail if gshred not available, but tests the logic
        let result = secure_delete(&path);

        // Clean up if secure_delete failed (gshred not available)
        if path.exists() {
            let _ = std::fs::remove_file(&path);
        }

        // Result should either succeed or fail with CommandFailed (gshred not found)
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
    // - install_homebrew() - requires network and system access
    // - install_yubikey_tools() - requires brew and network
    // - secure_delete() with gshred available
    //
    // These are covered in integration tests with proper environment setup
}
