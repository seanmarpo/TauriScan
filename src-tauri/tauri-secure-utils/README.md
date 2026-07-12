# TauriSecureUtils

`tauri-secure-utils` is a Rust utility library that provides secure, drop-in replacements for common backend operations in Tauri applications, specifically designed to defend against Path Traversal and Server-Side Request Forgery (SSRF) vulnerabilities.

## Exposed Functions

### Filesystem Operations (`fs.rs`)

**`resolve_safe_path(base_dir: &Path, user_input: &str) -> Result<PathBuf, String>`**

Safely resolves a user-provided path against a base directory, guaranteeing that the final resolved path strictly resides within the base boundary.
- **Defends against**: Path Traversal (e.g., `../../etc/passwd`), absolute path injection (`/etc/passwd`), and symlink escapes.
- **Mechanism**: It canonicalizes both the base directory and the requested path, verifying that the requested file's absolute path starts with the base directory's absolute path.

### Network Operations (`net.rs`)

**`validate_url_safe(url_str: &str) -> Result<Url, String>`**

Parses and validates a user-provided URL to ensure it is safe to fetch.
- **Defends against**: Server-Side Request Forgery (SSRF).
- **Mechanism**: Enforces `http` and `https` schemes. Crucially, it performs DNS resolution on the hostname and blocks the request if the host resolves to any private, loopback, link-local, or broadcast IP addresses (such as `127.0.0.1`, `192.168.1.1`, or `169.254.169.254`).
