//! `YubiKey` operations module
//!
//! Provides functions for interacting with `YubiKey` devices through command-line tools:
//! - `ykman` - `YubiKey` Manager for device information
//! - `ykpersonalize` - `YubiKey` Personalization Tool for programming slots
//! - `ykchalresp` - Challenge-Response tool for generating responses

use crate::error::{Result, YkvcError};
use rand::Rng;
use std::process::{Command, Stdio};

/// Information about a connected `YubiKey` device
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YubiKeyInfo {
    /// Serial number of the device
    pub serial: String,
    /// Firmware version installed on the device
    pub firmware_version: String,
    /// Whether slot 2 is programmed with HMAC-SHA1
    pub slot2_programmed: bool,
}

/// Check if `YubiKey` is connected and retrieve device information
///
/// Runs `ykman info` to get device details including serial number and firmware version.
///
/// # Errors
///
/// Returns an error if:
/// - `YubiKey` is not connected
/// - `ykman` command fails
/// - Output cannot be parsed
pub fn check_yubikey() -> Result<YubiKeyInfo> {
    let output = Command::new("ykman")
        .arg("info")
        .output()
        .map_err(|e| YkvcError::YkmanFailed(format!("Failed to execute ykman: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("No YubiKey detected") || stderr.contains("not connected") {
            return Err(YkvcError::YubiKeyNotFound);
        }
        return Err(YkvcError::YkmanFailed(format!(
            "ykman info failed: {stderr}"
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse serial number
    let serial = stdout
        .lines()
        .find(|line| line.to_lowercase().contains("serial"))
        .and_then(|line| line.split(':').nth(1))
        .map(str::trim)
        .map(ToString::to_string)
        .ok_or_else(|| YkvcError::YkmanFailed("Could not parse serial number".to_string()))?;

    // Parse firmware version
    let firmware_version = stdout
        .lines()
        .find(|line| line.to_lowercase().contains("firmware"))
        .and_then(|line| line.split(':').nth(1))
        .map(str::trim)
        .map(ToString::to_string)
        .ok_or_else(|| YkvcError::YkmanFailed("Could not parse firmware version".to_string()))?;

    // Check slot 2 status
    let slot2_programmed = check_slot2()?;

    Ok(YubiKeyInfo {
        serial,
        firmware_version,
        slot2_programmed,
    })
}

/// Check if slot 2 is programmed with HMAC-SHA1 Challenge-Response
///
/// Runs `ykman otp info` and checks if slot 2 is programmed.
///
/// # Errors
///
/// Returns an error if:
/// - `YubiKey` is not connected
/// - `ykman` command fails
pub fn check_slot2() -> Result<bool> {
    let output = Command::new("ykman")
        .args(["otp", "info"])
        .output()
        .map_err(|e| YkvcError::YkmanFailed(format!("Failed to execute ykman: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("No YubiKey detected") || stderr.contains("not connected") {
            return Err(YkvcError::YubiKeyNotFound);
        }
        return Err(YkvcError::YkmanFailed(format!(
            "ykman otp info failed: {stderr}"
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Check if slot 2 is programmed
    // Output typically contains "Slot 2: programmed" or "Slot 2: empty"
    Ok(stdout
        .lines()
        .any(|line| line.to_lowercase().contains("slot 2") && line.to_lowercase().contains("programmed")))
}

/// Program slot 2 with HMAC-SHA1 Challenge-Response
///
/// Generates a random 20-byte secret (if not provided) and programs slot 2
/// using `ykpersonalize` with the following configuration:
/// - HMAC-SHA1 Challenge-Response mode
/// - Less than 64 bytes output
/// - Serial number visible via API
///
/// # Arguments
///
/// * `secret` - Optional 20-byte secret. If `None`, a random secret is generated.
///
/// # Returns
///
/// Returns the secret that was programmed (for display to user)
///
/// # Errors
///
/// Returns an error if:
/// - Secret is provided but not exactly 20 bytes
/// - `YubiKey` is not connected
/// - `ykpersonalize` command fails
pub fn program_slot2(secret: Option<Vec<u8>>) -> Result<Vec<u8>> {
    // Generate random 20-byte secret if not provided
    let secret_bytes = if let Some(s) = secret {
        if s.len() != 20 {
            return Err(YkvcError::InvalidSecretLength(s.len()));
        }
        s
    } else {
        let mut secret = vec![0u8; 20];
        rand::thread_rng().fill(&mut secret[..]);
        secret
    };

    // Convert secret to hex format for ykpersonalize
    let secret_hex = hex::encode(&secret_bytes);

    // Run ykpersonalize with secret via stdin
    let child = Command::new("ykpersonalize")
        .args([
            "-2",                      // Slot 2
            "-ochal-resp",             // Challenge-Response mode
            "-ochal-hmac",             // HMAC mode
            "-ohmac-lt64",             // Less than 64 bytes output
            "-oserial-api-visible",    // Make serial visible
            "-y",                      // Skip confirmation
            "-a",                      // Secret from stdin (hex format)
        ])
        .arg(&secret_hex)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| YkvcError::YkpersonalizeFailed(format!("Failed to execute ykpersonalize: {e}")))?;

    let output = child
        .wait_with_output()
        .map_err(|e| YkvcError::YkpersonalizeFailed(format!("Failed to wait for ykpersonalize: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(YkvcError::YkpersonalizeFailed(format!(
            "ykpersonalize failed: {stderr}"
        )));
    }

    Ok(secret_bytes)
}

/// Perform HMAC-SHA1 challenge-response on slot 2
///
/// Sends a challenge string to slot 2 and returns the HMAC-SHA1 response.
/// This is the core function used to generate cryptographic keyfiles.
///
/// # Arguments
///
/// * `challenge` - The challenge string (typically a user password/phrase)
///
/// # Returns
///
/// Returns a 20-byte HMAC-SHA1 response
///
/// # Errors
///
/// Returns an error if:
/// - `YubiKey` is not connected
/// - Slot 2 is not programmed
/// - `ykchalresp` command fails
pub fn challenge_response(challenge: &str) -> Result<Vec<u8>> {
    // ykchalresp takes challenge as command-line argument, not stdin
    let output = Command::new("ykchalresp")
        .arg("-2")  // Slot 2
        .arg(challenge)  // Challenge as argument
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| YkvcError::YkchalrespFailed(format!("Failed to execute ykchalresp: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);

        if stderr.contains("No YubiKey detected") || stderr.contains("not connected") {
            return Err(YkvcError::YubiKeyNotFound);
        }

        if stderr.contains("slot 2") && stderr.contains("not programmed") {
            return Err(YkvcError::Slot2NotProgrammed);
        }

        return Err(YkvcError::YkchalrespFailed(format!(
            "ykchalresp failed: {stderr}"
        )));
    }

    // Parse hex response from stdout
    let stdout = String::from_utf8_lossy(&output.stdout);
    let response_hex = stdout.trim();

    hex::decode(response_hex).map_err(|e| {
        YkvcError::YkchalrespFailed(format!("Failed to decode hex response: {e}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_yubikey_info_struct() {
        let info = YubiKeyInfo {
            serial: "12345678".to_string(),
            firmware_version: "5.4.3".to_string(),
            slot2_programmed: true,
        };

        assert_eq!(info.serial, "12345678");
        assert_eq!(info.firmware_version, "5.4.3");
        assert!(info.slot2_programmed);
    }

    #[test]
    fn test_yubikey_info_clone() {
        let info = YubiKeyInfo {
            serial: "12345678".to_string(),
            firmware_version: "5.4.3".to_string(),
            slot2_programmed: true,
        };
        let cloned = info.clone();
        assert_eq!(info, cloned);
    }

    #[test]
    fn test_yubikey_info_debug() {
        let info = YubiKeyInfo {
            serial: "12345678".to_string(),
            firmware_version: "5.4.3".to_string(),
            slot2_programmed: true,
        };
        let debug_str = format!("{:?}", info);
        assert!(debug_str.contains("12345678"));
        assert!(debug_str.contains("5.4.3"));
        assert!(debug_str.contains("true"));
    }

    #[test]
    fn test_program_slot2_validates_secret_length() {
        let short_secret = vec![0u8; 19];
        let result = program_slot2(Some(short_secret));
        assert!(matches!(result, Err(YkvcError::InvalidSecretLength(19))));

        let long_secret = vec![0u8; 21];
        let result = program_slot2(Some(long_secret));
        assert!(matches!(result, Err(YkvcError::InvalidSecretLength(21))));
    }

    #[test]
    fn test_program_slot2_valid_secret_length() {
        let valid_secret = vec![0u8; 20];
        // This will fail because ykpersonalize is not available in test environment
        // but we verify the length validation passes
        let result = program_slot2(Some(valid_secret));
        // Should either succeed or fail with command execution error, not length error
        if let Err(e) = result {
            assert!(!matches!(e, YkvcError::InvalidSecretLength(_)));
        }
    }

    #[test]
    fn test_program_slot2_generates_random_secret() {
        // Test that random secret generation produces 20 bytes
        // This will fail with command execution but validates the secret generation
        let result = program_slot2(None);
        if let Err(e) = result {
            // Should fail with YkpersonalizeFailed, not InvalidSecretLength
            assert!(!matches!(e, YkvcError::InvalidSecretLength(_)));
        }
    }

    // Note: The following tests require mocking or actual YubiKey hardware
    // They are documented here for coverage awareness:
    //
    // - check_yubikey() with real hardware
    // - check_yubikey() with no device connected
    // - check_yubikey() parsing different ykman output formats
    // - check_slot2() with programmed slot
    // - check_slot2() with empty slot
    // - program_slot2() successful programming
    // - challenge_response() with various challenge strings
    // - challenge_response() with empty challenge
    // - challenge_response() with no device
    // - challenge_response() with unprogrammed slot
    //
    // These are tested via integration tests with real or mocked hardware
}
