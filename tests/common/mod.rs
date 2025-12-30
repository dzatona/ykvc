//! Common test utilities and helpers

use std::process::{Command, Output, ExitStatus};

/// Mock command output for testing
pub struct MockCommand {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub success: bool,
}

impl MockCommand {
    /// Create a successful command output
    #[must_use]
    pub fn success(stdout: &str) -> Self {
        Self {
            stdout: stdout.as_bytes().to_vec(),
            stderr: Vec::new(),
            success: true,
        }
    }

    /// Create a failed command output
    #[must_use]
    pub fn failure(stderr: &str) -> Self {
        Self {
            stdout: Vec::new(),
            stderr: stderr.as_bytes().to_vec(),
            success: false,
        }
    }

    /// Create output with both stdout and stderr
    #[must_use]
    pub fn with_output(stdout: &str, stderr: &str, success: bool) -> Self {
        Self {
            stdout: stdout.as_bytes().to_vec(),
            stderr: stderr.as_bytes().to_vec(),
            success,
        }
    }
}

/// Helper to create a temporary test file
pub fn create_temp_file(content: &[u8]) -> tempfile::NamedTempFile {
    use std::io::Write;

    let mut file = tempfile::NamedTempFile::new().expect("Failed to create temp file");
    file.write_all(content).expect("Failed to write to temp file");
    file.flush().expect("Failed to flush temp file");
    file
}

/// Helper to assert error message contains expected text
#[macro_export]
macro_rules! assert_error_contains {
    ($result:expr, $expected:expr) => {
        match $result {
            Ok(_) => panic!("Expected error, got Ok"),
            Err(e) => {
                let error_msg = e.to_string();
                assert!(
                    error_msg.contains($expected),
                    "Expected error message to contain '{}', but got: '{}'",
                    $expected,
                    error_msg
                );
            }
        }
    };
}
