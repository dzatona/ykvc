//! Integration tests for CLI interface

use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn test_cli_help() {
    let mut cmd = Command::cargo_bin("ykvc").unwrap();
    cmd.arg("--help");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("CLI utility for generating cryptographic keyfiles"))
        .stdout(predicate::str::contains("info"))
        .stdout(predicate::str::contains("slot2"))
        .stdout(predicate::str::contains("generate"))
        .stdout(predicate::str::contains("test"));
}

#[test]
fn test_cli_version() {
    let mut cmd = Command::cargo_bin("ykvc").unwrap();
    cmd.arg("--version");

    cmd.assert().success().stdout(predicate::str::contains("ykvc"));
}

#[test]
fn test_cli_slot2_help() {
    let mut cmd = Command::cargo_bin("ykvc").unwrap();
    cmd.args(["slot2", "--help"]);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("check"))
        .stdout(predicate::str::contains("program"))
        .stdout(predicate::str::contains("restore"));
}

#[test]
fn test_cli_generate_help() {
    let mut cmd = Command::cargo_bin("ykvc").unwrap();
    cmd.args(["generate", "--help"]);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("output"))
        .stdout(predicate::str::contains("-o"));
}

#[test]
fn test_cli_invalid_command() {
    let mut cmd = Command::cargo_bin("ykvc").unwrap();
    cmd.arg("invalid");

    cmd.assert().failure();
}

// Note: The following tests would require YubiKey hardware or mocking:
// - test_info_command_with_yubikey()
// - test_info_command_without_yubikey()
// - test_slot2_check_programmed()
// - test_slot2_check_not_programmed()
// - test_generate_command()
// - test_test_command()
//
// These require either:
// 1. Mock YubiKey device
// 2. Actual hardware
// 3. Test doubles for system commands
