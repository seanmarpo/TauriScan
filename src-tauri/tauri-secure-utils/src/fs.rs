use std::fs;
use std::path::{Path, PathBuf};

/// Safely resolves a user-provided path against a base directory.
/// Ensures the resolved path strictly resides within the base directory.
pub fn resolve_safe_path(base_dir: &Path, user_input: &str) -> Result<PathBuf, String> {
    // 1. Canonicalize the base directory to get an absolute, resolved path.
    let canonical_base = fs::canonicalize(base_dir)
        .map_err(|e| format!("Failed to resolve base directory: {}", e))?;

    // 2. Join the user input. If user_input is absolute, it will replace the base path.
    // That's exactly why we canonicalize and verify containment afterwards.
    let joined_path = canonical_base.join(user_input);

    // 3. Canonicalize the joined path. This resolves symlinks and logical traversals (`../`).
    // Note: this fails securely if the file does not exist.
    let canonical_target = fs::canonicalize(&joined_path)
        .map_err(|e| format!("Path does not exist or cannot be accessed: {}", e))?;

    // 4. Enforce the boundary. The target MUST be inside the base directory.
    if !canonical_target.starts_with(&canonical_base) {
        return Err("Path traversal detected: Target is outside the base directory".to_string());
    }

    Ok(canonical_target)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use std::os::unix::fs::symlink;

    #[test]
    fn test_valid_nested_file() {
        let temp_dir = TempDir::new().unwrap();
        let base = temp_dir.path();
        
        let valid_file_path = base.join("safe.txt");
        fs::write(&valid_file_path, "hello").unwrap();

        let resolved = resolve_safe_path(base, "safe.txt").unwrap();
        assert_eq!(resolved, fs::canonicalize(&valid_file_path).unwrap());
    }

    #[test]
    fn test_absolute_path_replacement_attempt() {
        let temp_dir = TempDir::new().unwrap();
        let base = temp_dir.path();
        
        // Attempting to read /etc/passwd directly
        let result = resolve_safe_path(base, "/etc/passwd");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Path traversal detected"));
    }

    #[test]
    fn test_dot_dot_traversal() {
        let temp_dir = TempDir::new().unwrap();
        let base = temp_dir.path();
        
        let result = resolve_safe_path(base, "../../../../../../etc/passwd");
        assert!(result.is_err());
    }

    #[test]
    fn test_symlink_escape() {
        let temp_dir = TempDir::new().unwrap();
        let base = temp_dir.path();
        
        let symlink_path = base.join("escape_link");
        // Create a symlink pointing outside the base directory
        symlink("/etc/passwd", &symlink_path).unwrap();

        // Trying to read the symlink should resolve to /etc/passwd and fail the boundary check
        let result = resolve_safe_path(base, "escape_link");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Path traversal detected"));
    }
}
