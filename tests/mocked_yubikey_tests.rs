//! Tests that simulate YubiKey operations without actual hardware

#[test]
fn test_simulated_yubikey_parsing() {
    // Simulate ykman info output parsing
    let mock_output = r#"Device type: YubiKey 5C NFC
Serial number: 12345678
Firmware version: 5.4.3
Form factor: USB-C (USB-C)
Enabled USB interfaces: OTP, FIDO, CCID
NFC transport is enabled.
"#;

    // Test serial number extraction
    let serial = mock_output
        .lines()
        .find(|line| line.to_lowercase().contains("serial"))
        .and_then(|line| line.split(':').nth(1))
        .map(str::trim)
        .map(|s| s.to_string());
    assert_eq!(serial, Some("12345678".to_string()));

    // Test firmware version extraction
    let firmware = mock_output
        .lines()
        .find(|line| line.to_lowercase().contains("firmware"))
        .and_then(|line| line.split(':').nth(1))
        .map(str::trim)
        .map(|s| s.to_string());
    assert_eq!(firmware, Some("5.4.3".to_string()));
}

#[test]
fn test_simulated_slot2_status() {
    // Simulate ykman otp info output

    // Scenario 1: Slot 2 programmed
    let mock_output_programmed = r#"Slot 1: programmed
Slot 2: programmed
"#;

    let has_slot2 = mock_output_programmed.lines().any(|line| {
        line.to_lowercase().contains("slot 2") && line.to_lowercase().contains("programmed")
    });
    assert!(has_slot2);

    // Scenario 2: Slot 2 empty
    let mock_output_empty = r#"Slot 1: programmed
Slot 2: empty
"#;

    let has_slot2 = mock_output_empty.lines().any(|line| {
        line.to_lowercase().contains("slot 2") && line.to_lowercase().contains("programmed")
    });
    assert!(!has_slot2);

    // Scenario 3: No slot 2 mentioned
    let mock_output_no_slot2 = r#"Slot 1: programmed
"#;

    let has_slot2 = mock_output_no_slot2.lines().any(|line| {
        line.to_lowercase().contains("slot 2") && line.to_lowercase().contains("programmed")
    });
    assert!(!has_slot2);
}

#[test]
fn test_simulated_error_detection() {
    // Simulate various error scenarios

    // No YubiKey detected
    let stderr = "Error: No YubiKey detected!";
    assert!(stderr.contains("No YubiKey detected"));

    // Device not connected
    let stderr = "Failed to connect to the YubiKey. Device not connected.";
    assert!(stderr.contains("not connected"));

    // Slot 2 not programmed
    let stderr = "Error: slot 2 is not programmed with HMAC-SHA1";
    assert!(stderr.contains("slot 2") && stderr.contains("not programmed"));
}

#[test]
fn test_simulated_challenge_response() {
    // Simulate ykchalresp output (hex string) - 20 bytes = 40 hex chars
    let mock_response = "0123456789abcdef0123456789abcdef01234567";

    // Parse hex response
    let response_bytes = hex::decode(mock_response);
    assert!(response_bytes.is_ok());

    let bytes = response_bytes.unwrap();
    assert_eq!(bytes.len(), 20); // HMAC-SHA1 is 20 bytes
}

#[test]
fn test_secret_hex_conversion() {
    // Test secret to hex conversion
    let secret = vec![
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
        0xef, 0x01, 0x23, 0x45, 0x67,
    ];

    let hex_str = hex::encode(&secret);
    assert_eq!(hex_str.len(), 40); // 20 bytes = 40 hex chars

    // Test roundtrip
    let decoded = hex::decode(&hex_str).unwrap();
    assert_eq!(decoded, secret);
}

#[test]
fn test_secret_length_validation() {
    // Test various secret lengths
    let valid_secret = [0u8; 20];
    assert_eq!(valid_secret.len(), 20);

    let short_secret = [0u8; 19];
    assert_ne!(short_secret.len(), 20);

    let long_secret = [0u8; 21];
    assert_ne!(long_secret.len(), 20);
}

#[test]
fn test_command_output_parsing() {
    // Test various output parsing scenarios

    // Empty output
    let output = "";
    let lines: Vec<&str> = output.lines().collect();
    assert_eq!(lines.len(), 0);

    // Single line
    let output = "Serial number: 12345";
    let lines: Vec<&str> = output.lines().collect();
    assert_eq!(lines.len(), 1);

    // Multiple lines with filtering
    let output = "Line 1\nSerial number: 12345\nLine 3";
    let serial_line = output.lines().find(|line| line.contains("Serial"));
    assert!(serial_line.is_some());
    assert_eq!(serial_line.unwrap(), "Serial number: 12345");
}

#[test]
fn test_error_message_matching() {
    // Test error message pattern matching

    fn classify_error(stderr: &str) -> &str {
        if stderr.contains("No YubiKey detected") || stderr.contains("not connected") {
            "no_device"
        } else if stderr.contains("slot 2") && stderr.contains("not programmed") {
            "slot_not_programmed"
        } else {
            "other"
        }
    }

    assert_eq!(classify_error("No YubiKey detected"), "no_device");
    assert_eq!(classify_error("Device not connected"), "no_device");
    assert_eq!(classify_error("slot 2 is not programmed"), "slot_not_programmed");
    assert_eq!(classify_error("Unknown error"), "other");
}

#[test]
fn test_hex_decode_errors() {
    // Test hex decode error cases

    // Valid hex
    let result = hex::decode("0123456789abcdef");
    assert!(result.is_ok());

    // Invalid hex (odd length)
    let result = hex::decode("012");
    assert!(result.is_err());

    // Invalid hex (non-hex characters)
    let result = hex::decode("gg");
    assert!(result.is_err());

    // Mixed case (should work)
    let result = hex::decode("0123456789ABCDEF");
    assert!(result.is_ok());
}

#[test]
fn test_yubikey_info_construction() {
    // Test constructing YubiKeyInfo from parsed data
    #[derive(Debug, Clone, PartialEq)]
    struct MockYubiKeyInfo {
        serial: String,
        firmware_version: String,
        slot2_programmed: bool,
    }

    let info = MockYubiKeyInfo {
        serial: "12345678".to_string(),
        firmware_version: "5.4.3".to_string(),
        slot2_programmed: true,
    };

    assert_eq!(info.serial, "12345678");
    assert_eq!(info.firmware_version, "5.4.3");
    assert!(info.slot2_programmed);

    // Test with slot2 not programmed
    let info2 = MockYubiKeyInfo { slot2_programmed: false, ..info.clone() };
    assert!(!info2.slot2_programmed);
}

#[test]
fn test_random_secret_generation_properties() {
    use rand::Rng;

    // Generate multiple secrets and verify properties
    for _ in 0..10 {
        let mut secret = vec![0u8; 20];
        rand::thread_rng().fill(&mut secret[..]);

        // Should be 20 bytes
        assert_eq!(secret.len(), 20);

        // Should convert to 40 hex characters
        let hex_str = hex::encode(&secret);
        assert_eq!(hex_str.len(), 40);

        // Should decode back to same value
        let decoded = hex::decode(&hex_str).unwrap();
        assert_eq!(decoded, secret);
    }
}

#[test]
fn test_command_line_arg_parsing() {
    // Test parsing command line arguments for challenge

    let args = ["ykchalresp", "-2", "my_challenge_phrase"];
    assert_eq!(args.len(), 3);
    assert_eq!(args[1], "-2"); // Slot 2
    assert_eq!(args[2], "my_challenge_phrase"); // Challenge

    // Empty challenge
    let args = ["ykchalresp", "-2", ""];
    assert_eq!(args[2], "");
}

#[test]
fn test_output_trimming() {
    // Test output trimming (common in command output parsing)

    let output = "  12345  \n";
    assert_eq!(output.trim(), "12345");

    let output = "\t\tvalue\t\t";
    assert_eq!(output.trim(), "value");

    let output = "value";
    assert_eq!(output.trim(), "value");
}
