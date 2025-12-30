//! Custom error types for YKVC

use thiserror::Error;

/// Result type alias for YKVC operations
pub type Result<T> = std::result::Result<T, YkvcError>;

/// Main error type for YKVC operations
#[derive(Error, Debug)]
#[allow(dead_code)] // Phase 1: Will be used in later phases
pub enum YkvcError {
    /// `YubiKey` device not found or not connected
    #[error("YubiKey not found. Please connect your YubiKey device.")]
    YubiKeyNotFound,

    /// `YubiKey` slot 2 is not programmed with HMAC-SHA1
    #[error("Slot 2 is not programmed. Run 'ykvc slot2 program' first.")]
    Slot2NotProgrammed,

    /// Required system dependency is missing
    #[error("Required dependency '{0}' is not installed")]
    DependencyMissing(String),

    /// Failed to execute system command
    #[error("Failed to execute command '{command}': {message}")]
    CommandFailed {
        /// The command that failed
        command: String,
        /// Error message from the command
        message: String,
    },

    /// Failed to install dependencies
    #[error("Failed to install dependencies: {0}")]
    InstallationFailed(String),

    /// Invalid hex string provided
    #[error("Invalid hex string: {0}")]
    InvalidHex(String),

    /// Invalid secret length (must be 20 bytes)
    #[error("Invalid secret length: expected 20 bytes, got {0}")]
    InvalidSecretLength(usize),

    /// `ykman` command failed
    #[error("ykman command failed: {0}")]
    YkmanFailed(String),

    /// `ykpersonalize` command failed
    #[error("ykpersonalize command failed: {0}")]
    YkpersonalizeFailed(String),

    /// `ykchalresp` command failed
    #[error("ykchalresp command failed: {0}")]
    YkchalrespFailed(String),

    /// File operation error
    #[error("File operation failed: {0}")]
    FileError(String),

    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Unsupported operating system
    #[error("Unsupported operating system: {0}")]
    UnsupportedOS(String),

    /// User cancelled operation
    #[error("Operation cancelled by user")]
    Cancelled,

    /// Generic error with context
    #[error("{0}")]
    Other(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_yubikey_not_found() {
        let err = YkvcError::YubiKeyNotFound;
        assert_eq!(err.to_string(), "YubiKey not found. Please connect your YubiKey device.");
    }

    #[test]
    fn test_slot2_not_programmed() {
        let err = YkvcError::Slot2NotProgrammed;
        assert_eq!(err.to_string(), "Slot 2 is not programmed. Run 'ykvc slot2 program' first.");
    }

    #[test]
    fn test_dependency_missing() {
        let err = YkvcError::DependencyMissing("ykman".to_string());
        assert_eq!(err.to_string(), "Required dependency 'ykman' is not installed");
    }

    #[test]
    fn test_command_failed() {
        let err = YkvcError::CommandFailed {
            command: "ykman info".to_string(),
            message: "command not found".to_string(),
        };
        assert_eq!(err.to_string(), "Failed to execute command 'ykman info': command not found");
    }

    #[test]
    fn test_installation_failed() {
        let err = YkvcError::InstallationFailed("brew not found".to_string());
        assert_eq!(err.to_string(), "Failed to install dependencies: brew not found");
    }

    #[test]
    fn test_invalid_hex() {
        let err = YkvcError::InvalidHex("not hex".to_string());
        assert_eq!(err.to_string(), "Invalid hex string: not hex");
    }

    #[test]
    fn test_invalid_secret_length() {
        let err = YkvcError::InvalidSecretLength(19);
        assert_eq!(err.to_string(), "Invalid secret length: expected 20 bytes, got 19");

        let err = YkvcError::InvalidSecretLength(21);
        assert_eq!(err.to_string(), "Invalid secret length: expected 20 bytes, got 21");
    }

    #[test]
    fn test_ykman_failed() {
        let err = YkvcError::YkmanFailed("connection timeout".to_string());
        assert_eq!(err.to_string(), "ykman command failed: connection timeout");
    }

    #[test]
    fn test_ykpersonalize_failed() {
        let err = YkvcError::YkpersonalizeFailed("access denied".to_string());
        assert_eq!(err.to_string(), "ykpersonalize command failed: access denied");
    }

    #[test]
    fn test_ykchalresp_failed() {
        let err = YkvcError::YkchalrespFailed("device error".to_string());
        assert_eq!(err.to_string(), "ykchalresp command failed: device error");
    }

    #[test]
    fn test_file_error() {
        let err = YkvcError::FileError("permission denied".to_string());
        assert_eq!(err.to_string(), "File operation failed: permission denied");
    }

    #[test]
    fn test_io_error_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let err: YkvcError = io_err.into();
        assert!(err.to_string().contains("I/O error"));
        assert!(err.to_string().contains("file not found"));
    }

    #[test]
    fn test_unsupported_os() {
        let err = YkvcError::UnsupportedOS("Windows".to_string());
        assert_eq!(err.to_string(), "Unsupported operating system: Windows");
    }

    #[test]
    fn test_cancelled() {
        let err = YkvcError::Cancelled;
        assert_eq!(err.to_string(), "Operation cancelled by user");
    }

    #[test]
    fn test_other() {
        let err = YkvcError::Other("custom error message".to_string());
        assert_eq!(err.to_string(), "custom error message");
    }

    #[test]
    fn test_error_debug() {
        let err = YkvcError::YubiKeyNotFound;
        let debug_str = format!("{err:?}");
        assert_eq!(debug_str, "YubiKeyNotFound");
    }

    #[test]
    fn test_result_type_alias() {
        fn returns_ok() -> Result<i32> {
            Ok(42)
        }

        fn returns_err() -> Result<i32> {
            Err(YkvcError::Cancelled)
        }

        assert!(returns_ok().is_ok());
        assert!(returns_err().is_err());
        assert_eq!(returns_ok().unwrap(), 42);
        assert!(matches!(returns_err(), Err(YkvcError::Cancelled)));
    }
}
