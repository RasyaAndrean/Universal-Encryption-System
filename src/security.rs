use std::time::{Duration, Instant};
use zeroize::Zeroize;

#[derive(Debug, thiserror::Error)]
pub enum SecurityError {
    #[error("Password too weak: {0}")]
    WeakPassword(String),
    #[error("Rate limit exceeded")]
    RateLimitExceeded,
    #[error("Memory security error: {0}")]
    MemorySecurity(String),
}

// Password strength requirements
const MIN_PASSWORD_LENGTH: usize = 12;
const MIN_UPPERCASE: usize = 2;
const MIN_LOWERCASE: usize = 2;
const MIN_DIGITS: usize = 2;
const MIN_SPECIAL_CHARS: usize = 1;

pub struct SecureString {
    data: Vec<u8>,
}

impl SecureString {
    pub fn new(s: &str) -> Self {
        SecureString {
            data: s.as_bytes().to_vec(),
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    pub fn as_str(&self) -> Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(&self.data)
    }
}

impl Drop for SecureString {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

pub struct RateLimiter {
    attempts: Vec<Instant>,
    max_attempts: usize,
    time_window: Duration,
}

impl RateLimiter {
    pub fn new(max_attempts: usize, time_window: Duration) -> Self {
        RateLimiter {
            attempts: Vec::new(),
            max_attempts,
            time_window,
        }
    }

    pub fn check_rate_limit(&mut self) -> Result<(), SecurityError> {
        let now = Instant::now();

        // Remove old attempts outside the time window
        self.attempts
            .retain(|&attempt| now.duration_since(attempt) < self.time_window);

        if self.attempts.len() >= self.max_attempts {
            return Err(SecurityError::RateLimitExceeded);
        }

        self.attempts.push(now);
        Ok(())
    }

    pub fn reset(&mut self) {
        self.attempts.clear();
    }
}

pub fn validate_password_strength(password: &str) -> Result<(), SecurityError> {
    if password.len() < MIN_PASSWORD_LENGTH {
        return Err(SecurityError::WeakPassword(format!(
            "Password must be at least {} characters long",
            MIN_PASSWORD_LENGTH
        )));
    }

    let mut uppercase = 0;
    let mut lowercase = 0;
    let mut digits = 0;
    let mut special = 0;

    for ch in password.chars() {
        if ch.is_ascii_uppercase() {
            uppercase += 1;
        } else if ch.is_ascii_lowercase() {
            lowercase += 1;
        } else if ch.is_ascii_digit() {
            digits += 1;
        } else if !ch.is_ascii_whitespace() {
            special += 1;
        }
    }

    if uppercase < MIN_UPPERCASE {
        return Err(SecurityError::WeakPassword(format!(
            "Password must contain at least {} uppercase letters",
            MIN_UPPERCASE
        )));
    }

    if lowercase < MIN_LOWERCASE {
        return Err(SecurityError::WeakPassword(format!(
            "Password must contain at least {} lowercase letters",
            MIN_LOWERCASE
        )));
    }

    if digits < MIN_DIGITS {
        return Err(SecurityError::WeakPassword(format!(
            "Password must contain at least {} digits",
            MIN_DIGITS
        )));
    }

    if special < MIN_SPECIAL_CHARS {
        return Err(SecurityError::WeakPassword(format!(
            "Password must contain at least {} special characters",
            MIN_SPECIAL_CHARS
        )));
    }

    // Check for common patterns
    let common_patterns = [
        "password",
        "123456",
        "qwerty",
        "abc123",
        "admin",
        "welcome",
        "letmein",
        "monkey",
        "dragon",
        "master",
        "login",
        "princess",
        "iloveyou",
        "trustno1",
        "sunshine",
        "shadow",
        "passw0rd",
        "football",
        "baseball",
        "superman",
        "batman",
        "access",
        "hello",
        "charlie",
        "donald",
        "654321",
        "1234567",
        "12345678",
        "123456789",
        "1234567890",
        "000000",
        "111111",
        "121212",
    ];

    let password_lower = password.to_lowercase();
    for pattern in &common_patterns {
        if password_lower.contains(pattern) {
            return Err(SecurityError::WeakPassword(
                "Password contains common weak patterns".to_string(),
            ));
        }
    }

    Ok(())
}

pub fn secure_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }

    result == 0
}

pub fn zeroize_memory<T: Zeroize>(data: &mut T) {
    data.zeroize();
}

pub fn secure_temp_file() -> Result<tempfile::NamedTempFile, std::io::Error> {
    tempfile::Builder::new()
        .prefix("secure_")
        .rand_bytes(16)
        .tempfile()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_strength_validation() {
        // Test weak passwords
        assert!(validate_password_strength("weak").is_err());
        assert!(validate_password_strength("nouppercase123!").is_err());
        assert!(validate_password_strength("NOLOWERCASE123!").is_err());
        assert!(validate_password_strength("NoDigits!").is_err());
        assert!(validate_password_strength("NoSpecialChars123").is_err());
        assert!(validate_password_strength("password123!").is_err());

        // Test strong password
        assert!(validate_password_strength("Str0ngP@ssw0rd123").is_ok());
        assert!(validate_password_strength("MySecureP@ss2023!").is_ok());
    }

    #[test]
    fn test_secure_compare() {
        let a = b"secret123";
        let b = b"secret123";
        let c = b"different123";

        assert!(secure_compare(a, b));
        assert!(!secure_compare(a, c));
        assert!(!secure_compare(b"short", b"longer"));
    }

    #[test]
    fn test_rate_limiter() {
        let mut limiter = RateLimiter::new(3, Duration::from_secs(1));

        // First 3 attempts should succeed
        assert!(limiter.check_rate_limit().is_ok());
        assert!(limiter.check_rate_limit().is_ok());
        assert!(limiter.check_rate_limit().is_ok());

        // 4th attempt should fail
        assert!(limiter.check_rate_limit().is_err());

        // Wait and try again
        std::thread::sleep(Duration::from_millis(1100));
        assert!(limiter.check_rate_limit().is_ok());
    }

    #[test]
    fn test_secure_string() {
        let password = "test_password_123";
        let secure_str = SecureString::new(password);

        assert_eq!(secure_str.as_str().unwrap(), password);

        // Test that memory is zeroized on drop
        // This is difficult to test directly, but the zeroize trait ensures it
    }
}
