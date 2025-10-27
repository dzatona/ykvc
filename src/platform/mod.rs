//! Platform-specific functionality and OS detection

pub mod linux;
pub mod macos;

use crate::error::Result;
#[cfg(any(target_os = "linux", not(any(target_os = "macos", target_os = "linux"))))]
use crate::error::YkvcError;
use colored::Colorize;

/// Required command-line dependencies (common for all platforms)
const REQUIRED_COMMANDS: &[&str] = &["ykman", "ykpersonalize", "ykchalresp"];

/// macOS-specific required commands
const REQUIRED_COMMANDS_MACOS: &[&str] = &["gshred"];

/// Supported operating systems
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OS {
    /// macOS (Darwin)
    MacOS,
    /// Ubuntu/Debian Linux
    #[allow(dead_code)] // Phase 1: Will be used when testing on Linux
    Ubuntu,
}

impl OS {
    /// Returns a human-readable name for the OS
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::MacOS => "macOS",
            Self::Ubuntu => "Ubuntu/Debian",
        }
    }
}

/// Detects the current operating system
///
/// # Errors
///
/// Returns an error if the OS is not supported (not macOS or Ubuntu/Debian)
#[allow(clippy::missing_const_for_fn)] // Cannot be const: uses Path::exists() on Linux
pub fn detect_os() -> Result<OS> {
    #[cfg(target_os = "macos")]
    {
        Ok(OS::MacOS)
    }

    #[cfg(target_os = "linux")]
    {
        // Check if running on Ubuntu/Debian by checking for apt
        if std::path::Path::new("/usr/bin/apt").exists()
            || std::path::Path::new("/usr/bin/apt-get").exists()
        {
            Ok(OS::Ubuntu)
        } else {
            Err(YkvcError::UnsupportedOS(
                "Only Ubuntu/Debian distributions are supported on Linux".to_string(),
            ))
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Err(YkvcError::UnsupportedOS(format!(
            "Unsupported operating system: {}",
            std::env::consts::OS
        )))
    }
}

/// Checks if all required dependencies are installed
///
/// # Arguments
///
/// * `os` - The detected operating system
///
/// # Errors
///
/// Returns an error if dependency checking fails
pub fn check_dependencies(os: OS) -> Result<Vec<String>> {
    let mut missing = Vec::new();

    // Check common dependencies
    for cmd in REQUIRED_COMMANDS {
        let exists = match os {
            OS::MacOS => macos::check_command(cmd)?,
            OS::Ubuntu => linux::check_command(cmd)?,
        };

        if !exists {
            missing.push((*cmd).to_string());
        }
    }

    // Check platform-specific dependencies
    if os == OS::MacOS {
        for cmd in REQUIRED_COMMANDS_MACOS {
            let exists = macos::check_command(cmd)?;
            if !exists {
                missing.push((*cmd).to_string());
            }
        }
    }

    Ok(missing)
}

/// Installs missing dependencies for the given operating system
///
/// # Arguments
///
/// * `os` - The detected operating system
///
/// # Errors
///
/// Returns an error if installation fails
pub fn install_dependencies(os: OS) -> Result<()> {
    match os {
        OS::MacOS => {
            // Check if Homebrew is installed
            if !macos::check_homebrew()? {
                println!("{} Homebrew is not installed", "[WARNING]".yellow().bold());
                macos::install_homebrew()?;
            }

            // Install YubiKey tools
            macos::install_yubikey_tools()?;
        }
        OS::Ubuntu => {
            // Install YubiKey tools
            linux::install_yubikey_tools()?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_os_name() {
        assert_eq!(OS::MacOS.name(), "macOS");
        assert_eq!(OS::Ubuntu.name(), "Ubuntu/Debian");
    }

    #[test]
    fn test_os_eq() {
        assert_eq!(OS::MacOS, OS::MacOS);
        assert_eq!(OS::Ubuntu, OS::Ubuntu);
        assert_ne!(OS::MacOS, OS::Ubuntu);
    }

    #[test]
    fn test_os_clone() {
        let os = OS::MacOS;
        let cloned = os;
        assert_eq!(os, cloned);
    }

    #[test]
    fn test_os_debug() {
        let os = OS::MacOS;
        let debug_str = format!("{os:?}");
        assert!(debug_str.contains("MacOS"));
    }

    #[test]
    fn test_detect_os() {
        #[cfg(target_os = "linux")]
        use crate::error::YkvcError;

        // This will pass on supported systems
        let result = detect_os();
        #[cfg(target_os = "linux")]
        assert!(result.is_ok() || matches!(result, Err(YkvcError::UnsupportedOS(_))));
        #[cfg(not(target_os = "linux"))]
        assert!(result.is_ok());
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_detect_os_macos() {
        let result = detect_os();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), OS::MacOS);
    }

    #[test]
    fn test_required_commands_constants() {
        assert!(REQUIRED_COMMANDS.contains(&"ykman"));
        assert!(REQUIRED_COMMANDS.contains(&"ykpersonalize"));
        assert!(REQUIRED_COMMANDS.contains(&"ykchalresp"));
        assert_eq!(REQUIRED_COMMANDS.len(), 3);
    }

    #[test]
    fn test_required_commands_macos_constants() {
        assert!(REQUIRED_COMMANDS_MACOS.contains(&"gshred"));
        assert_eq!(REQUIRED_COMMANDS_MACOS.len(), 1);
    }

    // Note: Full integration tests for check_dependencies() and install_dependencies()
    // require actual system commands or mocking, covered in integration tests:
    // - check_dependencies() with all commands present
    // - check_dependencies() with missing commands
    // - install_dependencies() for macOS (brew install)
    // - install_dependencies() for Linux (apt install)
}
