//! YKVC - `YubiKey` `VeraCrypt` CLI utility
//!
//! A command-line utility for generating cryptographic keyfiles using `YubiKey`
//! hardware tokens for use with `VeraCrypt` encrypted containers.

#![forbid(unsafe_code)]
#![deny(warnings, missing_docs, clippy::all, clippy::pedantic, clippy::nursery, clippy::cargo)]
#![allow(
    clippy::cargo_common_metadata,
    clippy::multiple_crate_versions, // Phase 1: Dependency versions from transitive deps
    clippy::unnecessary_wraps // Phase 1: Stubs will return Results in later phases
)]

mod error;
mod keyfile;
mod platform;
mod yubikey;

use clap::{Parser, Subcommand};
use colored::Colorize;
use error::Result;
use platform::OS;

/// `YubiKey` `VeraCrypt` CLI utility
#[derive(Parser, Debug)]
#[command(
    name = "ykvc",
    version,
    about = "YubiKey VeraCrypt keyfile generator",
    long_about = "A CLI utility for generating cryptographic keyfiles using YubiKey HMAC-SHA1 challenge-response"
)]
struct Cli {
    /// Subcommand to execute
    #[command(subcommand)]
    command: Commands,
}

/// Available commands
#[derive(Subcommand, Debug)]
enum Commands {
    /// Display `YubiKey` information
    Info,

    /// `YubiKey` slot 2 operations
    Slot2 {
        /// Slot 2 subcommand
        #[command(subcommand)]
        action: Slot2Commands,
    },

    /// Generate keyfile from challenge phrase
    Generate {
        /// Output path for keyfile (optional, defaults to `ykvc_keyfile_<timestamp>.key` in current directory)
        #[arg(short = 'o', long = "output")]
        output: Option<String>,
    },

    /// Test challenge-response functionality
    Test,
}

/// Slot 2 subcommands
#[derive(Subcommand, Debug)]
enum Slot2Commands {
    /// Check if slot 2 is programmed
    Check,

    /// Program slot 2 with random secret
    Program,

    /// Restore slot 2 from saved secret
    Restore {
        /// Secret key in hex format (40 hex characters = 20 bytes)
        secret: String,
    },
}

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    // Clear screen
    print!("\x1B[2J\x1B[1;1H");

    let cli = Cli::parse();

    // Detect OS
    let os = platform::detect_os()?;
    println!("{} Detected OS: {}", "[INFO]".blue().bold(), os.name());

    // Route to appropriate command handler
    match cli.command {
        Commands::Info => cmd_info(os),
        Commands::Slot2 { action } => match action {
            Slot2Commands::Check => cmd_slot2_check(os),
            Slot2Commands::Program => cmd_slot2_program(os),
            Slot2Commands::Restore { secret } => cmd_slot2_restore(os, &secret),
        },
        Commands::Generate { output } => cmd_generate(os, output.as_deref()),
        Commands::Test => cmd_test(os),
    }
}

/// Ensures all required dependencies are installed
///
/// # Arguments
///
/// * `os` - The detected operating system
///
/// # Errors
///
/// Returns an error if dependency installation fails or dependencies are still missing after installation
fn ensure_dependencies(os: platform::OS) -> Result<()> {
    println!("{} Checking dependencies...", "[INFO]".blue().bold());

    let missing = platform::check_dependencies(os)?;

    if missing.is_empty() {
        println!("{} All dependencies are installed", "[SUCCESS]".green().bold());
        return Ok(());
    }

    println!("{} Missing dependencies: {}", "[WARNING]".yellow().bold(), missing.join(", "));
    println!("{} Attempting to install missing dependencies...", "[INFO]".blue().bold());

    platform::install_dependencies(os)?;

    // Verify installation
    println!("{} Verifying installation...", "[INFO]".blue().bold());
    let still_missing = platform::check_dependencies(os)?;

    if !still_missing.is_empty() {
        return Err(error::YkvcError::InstallationFailed(format!(
            "Some dependencies are still missing after installation: {}",
            still_missing.join(", ")
        )));
    }

    println!("{} All dependencies installed successfully", "[SUCCESS]".green().bold());
    Ok(())
}

/// Handler for `ykvc info` command
fn cmd_info(os: OS) -> Result<()> {
    ensure_dependencies(os)?;

    println!("{} Checking YubiKey connection...", "[INFO]".blue().bold());

    let info = yubikey::check_yubikey()?;

    println!("{} YubiKey detected!", "[SUCCESS]".green().bold());
    println!();
    println!("{}", "YubiKey Information:".bold());
    println!("  Serial Number:     {}", info.serial.yellow());
    println!("  Firmware Version:  {}", info.firmware_version.yellow());
    println!(
        "  Slot 2 Status:     {}",
        if info.slot2_programmed {
            "Programmed".green().bold()
        } else {
            "Not Programmed".red().bold()
        }
    );
    println!();

    if !info.slot2_programmed {
        println!("{} Slot 2 is not programmed with HMAC-SHA1", "[WARNING]".yellow().bold());
        println!("Run {} to program slot 2", "ykvc slot2 program".cyan());
    }

    Ok(())
}

/// Handler for `ykvc slot2 check` command
fn cmd_slot2_check(os: OS) -> Result<()> {
    ensure_dependencies(os)?;

    println!("{} Checking slot 2 status...", "[INFO]".blue().bold());

    let is_programmed = yubikey::check_slot2()?;

    println!();
    if is_programmed {
        println!(
            "{} Slot 2 is programmed with HMAC-SHA1 Challenge-Response",
            "[SUCCESS]".green().bold()
        );
        println!();
        println!("You can now:");
        println!("  - Generate keyfiles with {}", "ykvc generate".cyan());
        println!("  - Test challenge-response with {}", "ykvc test".cyan());
    } else {
        println!("{} Slot 2 is not programmed", "[WARNING]".yellow().bold());
        println!();
        println!("To program slot 2, run: {}", "ykvc slot2 program".cyan());
    }

    Ok(())
}

/// Handler for `ykvc slot2 program` command
fn cmd_slot2_program(os: OS) -> Result<()> {
    ensure_dependencies(os)?;

    println!();
    println!(
        "{} {}",
        "[WARNING]".yellow().bold(),
        "This will overwrite any existing slot 2 configuration!".yellow()
    );
    println!();

    // Prompt for confirmation
    let confirmation = dialoguer::Confirm::new()
        .with_prompt("Do you want to continue?")
        .default(false)
        .interact()
        .map_err(|e| error::YkvcError::Other(format!("Failed to read user input: {e}")))?;

    if !confirmation {
        println!("{} Operation cancelled", "[INFO]".blue().bold());
        return Err(error::YkvcError::Cancelled);
    }

    println!();
    println!("{} Generating random secret...", "[INFO]".blue().bold());
    println!("{} Programming slot 2 with HMAC-SHA1 Challenge-Response...", "[INFO]".blue().bold());

    let secret = yubikey::program_slot2(None)?;

    println!();
    println!("{} Slot 2 configured successfully!", "[SUCCESS]".green().bold());
    println!();
    println!("{}", "=".repeat(70).yellow());
    println!("{}", "IMPORTANT: Save this secret securely!".red().bold());
    println!("{}", "=".repeat(70).yellow());
    println!();
    println!("Secret (hex):");
    println!("  {}", hex::encode(&secret).bright_yellow().bold());
    println!();
    println!("{}", "If you lose your YubiKey, you will need this secret".yellow());
    println!("{}", "to program a new YubiKey with the same configuration.".yellow());
    println!();
    println!("Store it in a password manager or write it down securely.");
    println!();
    println!("To restore on a new YubiKey:");
    println!("  {} {}", "ykvc slot2 restore".cyan(), "<secret-hex>".bright_black());
    println!();
    println!("{}", "=".repeat(70).yellow());
    println!();

    // Wait for user acknowledgment
    dialoguer::Input::<String>::new()
        .with_prompt("Press Enter to continue")
        .allow_empty(true)
        .interact_text()
        .map_err(|e| error::YkvcError::Other(format!("Failed to read user input: {e}")))?;

    Ok(())
}

/// Handler for `ykvc slot2 restore <secret>` command
fn cmd_slot2_restore(os: OS, secret: &str) -> Result<()> {
    ensure_dependencies(os)?;

    println!("{} Validating secret...", "[INFO]".blue().bold());

    // Parse and validate hex secret
    let secret_bytes = hex::decode(secret.trim())
        .map_err(|e| error::YkvcError::InvalidHex(format!("Invalid hex string: {e}")))?;

    if secret_bytes.len() != 20 {
        return Err(error::YkvcError::InvalidSecretLength(secret_bytes.len()));
    }

    println!("{} Secret is valid (20 bytes)", "[SUCCESS]".green().bold());
    println!();
    println!(
        "{} {}",
        "[WARNING]".yellow().bold(),
        "This will overwrite any existing slot 2 configuration!".yellow()
    );
    println!();

    // Prompt for confirmation
    let confirmation = dialoguer::Confirm::new()
        .with_prompt("Do you want to continue?")
        .default(false)
        .interact()
        .map_err(|e| error::YkvcError::Other(format!("Failed to read user input: {e}")))?;

    if !confirmation {
        println!("{} Operation cancelled", "[INFO]".blue().bold());
        return Err(error::YkvcError::Cancelled);
    }

    println!();
    println!("{} Programming slot 2 with provided secret...", "[INFO]".blue().bold());

    yubikey::program_slot2(Some(secret_bytes))?;

    println!();
    println!("{} Slot 2 restored successfully!", "[SUCCESS]".green().bold());
    println!();
    println!("You can now generate keyfiles with the same challenge phrases");
    println!("as on the original YubiKey.");
    println!();

    Ok(())
}

/// Handler for `ykvc generate` command
fn cmd_generate(os: OS, output: Option<&str>) -> Result<()> {
    ensure_dependencies(os)?;

    // Check YubiKey connection and slot 2 status
    println!("{} Checking YubiKey...", "[INFO]".blue().bold());
    let info = yubikey::check_yubikey()?;

    if !info.slot2_programmed {
        println!();
        println!("{} Slot 2 is not programmed with HMAC-SHA1", "[ERROR]".red().bold());
        println!();
        println!("Please program slot 2 first:");
        println!("  {}", "ykvc slot2 program".cyan());
        println!();
        return Err(error::YkvcError::Slot2NotProgrammed);
    }

    println!("{} YubiKey ready (Serial: {})", "[SUCCESS]".green().bold(), info.serial.yellow());
    println!();

    // Prompt for challenge phrase (with password input, no echo)
    let challenge = dialoguer::Password::new()
        .with_prompt("Enter challenge phrase")
        .interact()
        .map_err(|e| error::YkvcError::Other(format!("Failed to read challenge phrase: {e}")))?;

    println!();

    // Generate keyfile
    let output_path = output.map(std::path::PathBuf::from);
    let keyfile_path = keyfile::generate_keyfile(&challenge, output_path)?;

    // Get file size
    let file_size = std::fs::metadata(&keyfile_path)
        .map_err(|e| error::YkvcError::FileError(format!("Failed to get keyfile metadata: {e}")))?
        .len();

    println!();
    println!("{} Keyfile generated successfully!", "[SUCCESS]".green().bold());
    println!();
    println!("{}", "Keyfile Information:".bold());
    println!("  Path:  {}", keyfile_path.display().to_string().green());
    println!("  Size:  {} bytes", file_size.to_string().yellow());
    println!();
    println!("Use this keyfile with VeraCrypt to mount your container.");
    println!();

    // Prompt: "Press Enter after using the keyfile to securely delete it..."
    dialoguer::Input::<String>::new()
        .with_prompt("Press Enter after using the keyfile to securely delete it")
        .allow_empty(true)
        .interact_text()
        .map_err(|e| error::YkvcError::Other(format!("Failed to read user input: {e}")))?;

    println!();

    // Securely delete keyfile
    keyfile::secure_delete(&keyfile_path)?;

    println!();
    println!("{} Operation completed", "[SUCCESS]".green().bold());
    println!();

    Ok(())
}

/// Handler for `ykvc test` command
fn cmd_test(os: OS) -> Result<()> {
    ensure_dependencies(os)?;

    // Check YubiKey connection and slot 2 status
    println!("{} Checking YubiKey...", "[INFO]".blue().bold());
    let info = yubikey::check_yubikey()?;

    if !info.slot2_programmed {
        println!();
        println!("{} Slot 2 is not programmed with HMAC-SHA1", "[ERROR]".red().bold());
        println!();
        println!("Please program slot 2 first:");
        println!("  {}", "ykvc slot2 program".cyan());
        println!();
        return Err(error::YkvcError::Slot2NotProgrammed);
    }

    println!("{} YubiKey ready (Serial: {})", "[SUCCESS]".green().bold(), info.serial.yellow());
    println!();

    // Prompt for test challenge phrase (with password input)
    let challenge = dialoguer::Password::new()
        .with_prompt("Enter test challenge phrase")
        .interact()
        .map_err(|e| error::YkvcError::Other(format!("Failed to read challenge phrase: {e}")))?;

    println!();
    println!("{} Performing challenge-response...", "[INFO]".blue().bold());

    // Call challenge_response
    let response = yubikey::challenge_response(&challenge)?;

    // Display response in hex format
    println!();
    println!("{} Challenge-Response Test", "[SUCCESS]".green().bold());
    println!();
    println!("{}", "Test Results:".bold());
    println!(
        "  Challenge:  {}",
        if challenge.is_empty() {
            "<empty>".bright_black().to_string()
        } else {
            format!("{} characters", challenge.len()).yellow().to_string()
        }
    );
    println!("  Response (hex):");
    println!("    {}", hex::encode(&response).bright_yellow());
    println!("  Response (bytes):  {}", response.len().to_string().yellow());
    println!();
    println!("This response can be used as a cryptographic keyfile.");
    println!();

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_parsing_info() {
        let cli = Cli::parse_from(["ykvc", "info"]);
        assert!(matches!(cli.command, Commands::Info));
    }

    #[test]
    fn test_cli_parsing_test() {
        let cli = Cli::parse_from(["ykvc", "test"]);
        assert!(matches!(cli.command, Commands::Test));
    }

    #[test]
    fn test_cli_parsing_slot2_check() {
        let cli = Cli::parse_from(["ykvc", "slot2", "check"]);
        match cli.command {
            Commands::Slot2 { action } => {
                assert!(matches!(action, Slot2Commands::Check));
            }
            _ => panic!("Expected Slot2 command"),
        }
    }

    #[test]
    fn test_cli_parsing_slot2_program() {
        let cli = Cli::parse_from(["ykvc", "slot2", "program"]);
        match cli.command {
            Commands::Slot2 { action } => {
                assert!(matches!(action, Slot2Commands::Program));
            }
            _ => panic!("Expected Slot2 command"),
        }
    }

    #[test]
    fn test_cli_parsing_slot2_restore() {
        let secret = "0123456789abcdef01234567890abcdef0123456";
        let cli = Cli::parse_from(["ykvc", "slot2", "restore", secret]);
        match cli.command {
            Commands::Slot2 { action } => match action {
                Slot2Commands::Restore { secret: s } => {
                    assert_eq!(s, secret);
                }
                _ => panic!("Expected Restore command"),
            },
            _ => panic!("Expected Slot2 command"),
        }
    }

    #[test]
    fn test_cli_parsing_generate_no_output() {
        let cli = Cli::parse_from(["ykvc", "generate"]);
        match cli.command {
            Commands::Generate { output } => {
                assert!(output.is_none());
            }
            _ => panic!("Expected Generate command"),
        }
    }

    #[test]
    fn test_cli_parsing_generate_with_output() {
        let cli = Cli::parse_from(["ykvc", "generate", "-o", "/path/to/keyfile.key"]);
        match cli.command {
            Commands::Generate { output } => {
                assert_eq!(output, Some("/path/to/keyfile.key".to_string()));
            }
            _ => panic!("Expected Generate command"),
        }
    }

    #[test]
    fn test_cli_parsing_generate_with_output_long() {
        let cli = Cli::parse_from(["ykvc", "generate", "--output", "/path/to/keyfile.key"]);
        match cli.command {
            Commands::Generate { output } => {
                assert_eq!(output, Some("/path/to/keyfile.key".to_string()));
            }
            _ => panic!("Expected Generate command"),
        }
    }

    #[test]
    fn test_cli_debug() {
        let cli = Cli::parse_from(["ykvc", "info"]);
        let debug_str = format!("{cli:?}");
        assert!(debug_str.contains("Cli"));
        assert!(debug_str.contains("Info"));
    }

    #[test]
    fn test_commands_enum_debug() {
        let cmd = Commands::Info;
        let debug_str = format!("{cmd:?}");
        assert_eq!(debug_str, "Info");
    }

    #[test]
    fn test_slot2_commands_enum_debug() {
        let cmd = Slot2Commands::Check;
        let debug_str = format!("{cmd:?}");
        assert_eq!(debug_str, "Check");

        let cmd = Slot2Commands::Program;
        let debug_str = format!("{cmd:?}");
        assert_eq!(debug_str, "Program");

        let cmd = Slot2Commands::Restore { secret: "test".to_string() };
        let debug_str = format!("{cmd:?}");
        assert!(debug_str.contains("Restore"));
        assert!(debug_str.contains("test"));
    }

    // Note: Integration tests for command handlers (cmd_*) require:
    // - Mocked platform functions
    // - Mocked YubiKey operations
    // - Mocked user input (dialoguer)
    //
    // These are tested via integration tests in tests/ directory:
    // - cmd_info() with/without YubiKey
    // - cmd_slot2_check() with programmed/unprogrammed slot
    // - cmd_slot2_program() with user confirmation
    // - cmd_slot2_restore() with valid/invalid secrets
    // - cmd_generate() full workflow
    // - cmd_test() with YubiKey response
    // - ensure_dependencies() with missing/present dependencies
}
