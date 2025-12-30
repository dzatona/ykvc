//! Tests for command checking functionality

use std::process::Command;

#[test]
fn test_command_existence_pattern() {
    // Test the pattern used in check_command

    // Test with a command that should exist
    let output = Command::new("sh").arg("-c").arg("command -v sh").output();
    assert!(output.is_ok());

    if let Ok(output) = output {
        // sh should exist on Unix systems
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        assert!(output.status.success());
    }

    // Test with a command that doesn't exist
    let output = Command::new("sh")
        .arg("-c")
        .arg("command -v definitely_nonexistent_command_12345")
        .output();
    assert!(output.is_ok());

    if let Ok(output) = output {
        // Should fail (command not found)
        assert!(!output.status.success());
    }
}

#[test]
fn test_multiple_command_checks() {
    // Test checking multiple commands (as done in check_dependencies)

    let commands = ["sh", "echo", "cat"];
    let mut all_exist = true;

    for cmd in commands {
        let output = Command::new("sh").arg("-c").arg(format!("command -v {cmd}")).output();
        if let Ok(output) = output {
            if !output.status.success() {
                all_exist = false;
            }
        }
    }

    // On Unix systems, these basic commands should exist
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    assert!(all_exist);
}

#[test]
fn test_command_output_handling() {
    // Test handling command output

    let output = Command::new("echo").arg("test").output().unwrap();

    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout.trim(), "test");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.is_empty());
}

#[test]
fn test_command_status_checking() {
    // Test checking command status (used in installation functions)

    // Successful command
    let status = Command::new("true").status();
    assert!(status.is_ok());
    assert!(status.unwrap().success());

    // Failing command
    let status = Command::new("false").status();
    assert!(status.is_ok());
    assert!(!status.unwrap().success());
}

#[test]
fn test_command_error_handling() {
    // Test command execution error handling

    // Non-existent command
    let result = Command::new("nonexistent_command_xyz123").output();
    assert!(result.is_err());

    // Valid command with invalid args (should execute but fail)
    let result = Command::new("ls").arg("/nonexistent/path/xyz123").output();
    assert!(result.is_ok());
    if let Ok(output) = result {
        assert!(!output.status.success());
    }
}

#[test]
#[cfg(target_os = "macos")]
fn test_macos_command_patterns() {
    // Test macOS-specific command patterns

    // Test command -v pattern
    let output = Command::new("sh").arg("-c").arg("command -v sh").output();
    assert!(output.is_ok());
    if let Ok(output) = output {
        assert!(output.status.success());
    }

    // Test which (alternative to command -v)
    let output = Command::new("which").arg("sh").output();
    if let Ok(output) = output {
        assert!(output.status.success());
    }
}

#[test]
#[cfg(target_os = "linux")]
fn test_linux_command_patterns() {
    // Test Linux-specific command patterns

    // Test command -v pattern
    let output = Command::new("sh").arg("-c").arg("command -v sh").output();
    assert!(output.is_ok());
    if let Ok(output) = output {
        assert!(output.status.success());
    }

    // Test which (alternative to command -v)
    let output = Command::new("which").arg("sh").output();
    if let Ok(output) = output {
        assert!(output.status.success());
    }
}

#[test]
fn test_vec_string_operations() {
    // Test Vec<String> operations used in check_dependencies

    let missing = ["ykman".to_string(), "ykpersonalize".to_string()];

    assert_eq!(missing.len(), 2);
    assert!(missing.contains(&"ykman".to_string()));
    assert!(!missing.contains(&"other".to_string()));

    // Test is_empty
    assert!(!missing.is_empty());

    let empty: Vec<String> = Vec::new();
    assert!(empty.is_empty());

    // Test join
    let joined = missing.join(", ");
    assert_eq!(joined, "ykman, ykpersonalize");
}

#[test]
fn test_conditional_command_execution() {
    // Test conditional command execution patterns

    fn check_and_report(cmd: &str) -> bool {
        let output = Command::new("sh").arg("-c").arg(format!("command -v {cmd}")).output();
        output.map(|o| o.status.success()).unwrap_or(false)
    }

    // Should exist
    assert!(check_and_report("sh"));

    // Should not exist
    assert!(!check_and_report("nonexistent_xyz"));
}

#[test]
fn test_command_chaining_logic() {
    // Test logic for chaining command checks

    let required_commands = ["sh", "echo", "cat"];
    let mut missing = Vec::new();

    for cmd in required_commands {
        let output = Command::new("sh").arg("-c").arg(format!("command -v {cmd}")).output();
        let exists = output.map(|o| o.status.success()).unwrap_or(false);

        if !exists {
            missing.push(cmd.to_string());
        }
    }

    // On Unix systems, these should all exist
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    assert!(missing.is_empty());
}

#[test]
fn test_command_output_conversion() {
    // Test output conversion patterns

    let output = Command::new("echo").arg("test").output().unwrap();

    // Convert to String
    let stdout_str = String::from_utf8_lossy(&output.stdout);
    assert!(stdout_str.contains("test"));

    // Trim whitespace
    let trimmed = stdout_str.trim();
    assert_eq!(trimmed, "test");

    // Check if empty
    let stderr_str = String::from_utf8_lossy(&output.stderr);
    assert!(stderr_str.is_empty() || stderr_str.trim().is_empty());
}

#[test]
fn test_spawn_vs_output() {
    // Test difference between spawn and output

    // Using output() - waits for completion
    let output = Command::new("echo").arg("test").output();
    assert!(output.is_ok());

    // Using spawn() then wait - equivalent but more flexible
    let child = Command::new("echo").arg("test").spawn();
    assert!(child.is_ok());

    if let Ok(mut child) = child {
        let result = child.wait();
        assert!(result.is_ok());
        assert!(result.unwrap().success());
    }
}
