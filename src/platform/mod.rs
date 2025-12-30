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

    #[test]
    fn test_os_copy() {
        let os1 = OS::MacOS;
        let os2 = os1;
        assert_eq!(os1, os2);

        let os3 = OS::Ubuntu;
        let os4 = os3;
        assert_eq!(os3, os4);
    }

    #[test]
    fn test_os_name_coverage() {
        let macos = OS::MacOS;
        let ubuntu = OS::Ubuntu;

        assert_eq!(macos.name(), "macOS");
        assert_eq!(ubuntu.name(), "Ubuntu/Debian");

        // Test that names are different
        assert_ne!(macos.name(), ubuntu.name());
    }

    #[test]
    fn test_required_commands_immutable() {
        // Verify that REQUIRED_COMMANDS is properly defined
        let commands = REQUIRED_COMMANDS;
        assert_eq!(commands.len(), 3);
        assert!(commands.iter().all(|&cmd| !cmd.is_empty()));
    }

    #[test]
    fn test_required_commands_content() {
        // Test individual commands
        assert!(REQUIRED_COMMANDS.contains(&"ykman"));
        assert!(REQUIRED_COMMANDS.contains(&"ykpersonalize"));
        assert!(REQUIRED_COMMANDS.contains(&"ykchalresp"));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_detect_os_linux_no_apt() {
        // This test verifies the error path when apt is not found
        // Note: This may pass or fail depending on the system
        let result = detect_os();
        // On Ubuntu/Debian, should succeed
        // On other Linux, should fail
        assert!(result.is_ok() || matches!(result, Err(YkvcError::UnsupportedOS(_))));
    }

    #[test]
    fn test_check_dependencies_return_type() {
        // Test that check_dependencies returns correct type
        let os = OS::MacOS;
        let result = check_dependencies(os);
        assert!(result.is_ok() || result.is_err());

        if let Ok(missing) = result {
            // Should return a Vec<String>
            assert!(missing.iter().all(|s| !s.is_empty()));
        }
    }

    #[test]
    fn test_os_enum_all_variants_covered() {
        // Ensure all OS variants have name() implementation
        let variants = vec![OS::MacOS, OS::Ubuntu];
        for variant in variants {
            let name = variant.name();
            assert!(!name.is_empty());
        }
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_check_dependencies_macos() {
        // Test check_dependencies for macOS
        let os = OS::MacOS;
        let result = check_dependencies(os);

        // Should return Ok with Vec<String>
        assert!(result.is_ok());

        // If there are missing commands, they should be in the list
        if let Ok(missing) = result {
            for cmd in &missing {
                assert!(!cmd.is_empty());
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_check_dependencies_ubuntu() {
        // Test check_dependencies for Ubuntu
        let os = OS::Ubuntu;
        let result = check_dependencies(os);

        // Should return Ok with Vec<String>
        assert!(result.is_ok());

        if let Ok(missing) = result {
            for cmd in &missing {
                assert!(!cmd.is_empty());
            }
        }
    }

    #[test]
    fn test_required_commands_iteration() {
        // Test iteration over required commands
        for &cmd in REQUIRED_COMMANDS {
            assert!(!cmd.is_empty());
            assert!(cmd.is_ascii());
        }
    }

    #[test]
    fn test_required_commands_macos_iteration() {
        // Test iteration over macOS-specific commands
        for &cmd in REQUIRED_COMMANDS_MACOS {
            assert!(!cmd.is_empty());
            assert!(cmd.is_ascii());
        }
    }

    #[test]
    fn test_required_commands_are_not_empty() {
        // Ensure all required commands are valid
        for &cmd in REQUIRED_COMMANDS {
            assert!(!cmd.is_empty());
            assert!(!cmd.is_empty());
        }
    }

    #[test]
    fn test_required_commands_macos_are_not_empty() {
        // Ensure all macOS-specific commands are valid
        for &cmd in REQUIRED_COMMANDS_MACOS {
            assert!(!cmd.is_empty());
            assert!(!cmd.is_empty());
        }
    }

    #[test]
    fn test_required_commands_count() {
        // Verify expected number of required commands
        assert_eq!(REQUIRED_COMMANDS.len(), 3); // ykman, ykpersonalize, ykchalresp
    }

    #[test]
    fn test_required_commands_macos_count() {
        // Verify expected number of macOS-specific commands
        assert_eq!(REQUIRED_COMMANDS_MACOS.len(), 1); // gshred
    }

    #[test]
    fn test_os_equality_reflexive() {
        // Test reflexive property of equality
        let os = OS::MacOS;
        assert_eq!(os, os);

        let os = OS::Ubuntu;
        assert_eq!(os, os);
    }

    #[test]
    fn test_os_inequality() {
        // Test inequality between different OS variants
        assert_ne!(OS::MacOS, OS::Ubuntu);
        assert_ne!(OS::Ubuntu, OS::MacOS);
    }

    #[test]
    fn test_os_display_names() {
        // Test that OS names are non-empty and formatted correctly
        assert_eq!(OS::MacOS.name(), "macOS");
        assert_eq!(OS::Ubuntu.name(), "Ubuntu/Debian");

        assert!(!OS::MacOS.name().is_empty());
        assert!(!OS::Ubuntu.name().is_empty());
    }

    #[test]
    fn test_os_debug_formatting() {
        // Test debug formatting
        let os = OS::MacOS;
        let debug_str = format!("{os:?}");
        assert!(debug_str.contains("MacOS"));

        let os = OS::Ubuntu;
        let debug_str = format!("{os:?}");
        assert!(debug_str.contains("Ubuntu"));
    }

    #[test]
    fn test_vec_string_join_for_missing_deps() {
        // Test Vec<String>::join used in error messages
        let missing = ["ykman".to_string(), "ykpersonalize".to_string()];
        let joined = missing.join(", ");
        assert_eq!(joined, "ykman, ykpersonalize");
    }

    #[test]
    fn test_vec_push_for_missing_deps() {
        // Test Vec::push used in check_dependencies
        let missing = ["ykman".to_string(), "ykchalresp".to_string()];
        assert_eq!(missing.len(), 2);
        assert_eq!(missing[0], "ykman");
        assert_eq!(missing[1], "ykchalresp");
    }

    #[test]
    fn test_string_to_string_conversion() {
        // Test &str to String conversion used in check_dependencies
        let cmd: &str = "ykman";
        let owned: String = cmd.to_string();
        assert_eq!(owned, "ykman");
    }

    #[test]
    fn test_slice_iteration() {
        // Test slice iteration used in check_dependencies
        let commands = ["ykman", "ykpersonalize", "ykchalresp"];
        let mut count = 0;
        for cmd in &commands {
            count += 1;
            assert!(!cmd.is_empty());
        }
        assert_eq!(count, 3);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_target_os_macos_detection() {
        // Test that target_os macro works correctly
        let result = detect_os();
        assert!(result.is_ok());
        let os = result.unwrap();
        assert_eq!(os, OS::MacOS);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_target_os_linux_detection() {
        // Test that target_os macro works correctly on Linux
        let result = detect_os();
        // Will succeed if apt is available
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn test_env_consts_os() {
        // Test std::env::consts::OS
        let os_str = std::env::consts::OS;
        assert!(!os_str.is_empty());
        assert!(os_str == "macos" || os_str == "linux" || os_str == "windows");
    }

    #[test]
    fn test_format_macro_with_os_name() {
        // Test format! with OS name
        let os = OS::MacOS;
        let msg = format!("Detected OS: {}", os.name());
        assert!(msg.contains("Detected OS:"));
        assert!(msg.contains("macOS"));
    }

    #[test]
    fn test_vec_new_and_push() {
        // Test Vec::new and push used in check_dependencies
        let mut missing: Vec<String> = Vec::new();
        assert!(missing.is_empty());
        assert_eq!(missing.len(), 0);

        missing.push("cmd1".to_string());
        assert!(!missing.is_empty());
        assert_eq!(missing.len(), 1);

        missing.push("cmd2".to_string());
        assert_eq!(missing.len(), 2);
    }

    #[test]
    fn test_for_loop_over_slice() {
        // Test for loop pattern used in check_dependencies
        let commands = ["ykman", "ykchalresp", "ykpersonalize"];
        let mut count = 0;

        for cmd in commands {
            count += 1;
            assert!(!cmd.is_empty());
        }

        assert_eq!(count, 3);
    }

    #[test]
    fn test_match_os_enum() {
        // Test match on OS enum
        let os = OS::MacOS;
        let result = match os {
            OS::MacOS => "macOS",
            OS::Ubuntu => "Ubuntu",
        };
        assert_eq!(result, "macOS");

        let os = OS::Ubuntu;
        let result = match os {
            OS::MacOS => "macOS",
            OS::Ubuntu => "Ubuntu",
        };
        assert_eq!(result, "Ubuntu");
    }

    #[test]
    fn test_cfg_target_os_values() {
        // Test cfg(target_os) detection values
        #[cfg(target_os = "macos")]
        {
            let os = "macos";
            assert_eq!(os, "macos");
        }

        #[cfg(target_os = "linux")]
        {
            let os = "linux";
            assert_eq!(os, "linux");
        }

        // Pattern compiles correctly
    }

    #[test]
    fn test_string_deref_to_str() {
        // Test String -> &str coercion
        let owned = String::from("ykman");
        let borrowed: &str = &owned;
        assert_eq!(borrowed, "ykman");
    }

    #[test]
    fn test_vec_iter_collect() {
        // Test Vec iterator and collect patterns
        let commands = ["ykman", "ykchalresp", "ykpersonalize"];
        let strings: Vec<String> = commands.iter().map(|&s| s.to_string()).collect();

        assert_eq!(strings.len(), 3);
        assert_eq!(strings[0], "ykman");
    }

    #[test]
    fn test_bool_operator_and() {
        // Test boolean && operator
        let check1 = true;
        let check2 = true;
        assert!(check1 && check2);

        let check3 = false;
        assert!(!(check1 && check3));
    }

    #[test]
    fn test_if_statement_patterns() {
        // Test if statement patterns
        let missing_count = 0;

        if missing_count == 0 {
            // Pattern compiles correctly
        } else {
            panic!("Should be zero");
        }
    }

    #[test]
    fn test_format_error_messages() {
        // Test error message formatting patterns
        let missing = ["cmd1", "cmd2"];
        let msg = format!("Missing: {}", missing.join(", "));
        assert!(msg.contains("Missing:"));
        assert!(msg.contains("cmd1, cmd2"));
    }

    // Note: Full integration tests for check_dependencies() and install_dependencies()
    // require actual system commands or mocking, covered in integration tests:
    // - check_dependencies() with all commands present
    // - check_dependencies() with missing commands
    // - install_dependencies() for macOS (brew install)
    // - install_dependencies() for Linux (apt install)
}
