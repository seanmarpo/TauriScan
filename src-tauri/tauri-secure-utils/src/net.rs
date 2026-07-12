use std::net::{IpAddr, ToSocketAddrs};
use url::Url;

/// Parses and validates a URL, explicitly blocking SSRF attacks by preventing
/// resolution to internal, private, or loopback IP addresses.
pub fn validate_url_safe(url_str: &str) -> Result<Url, String> {
    let parsed_url = Url::parse(url_str).map_err(|e| format!("Invalid URL: {}", e))?;

    // 1. Enforce scheme (Only allow HTTP/HTTPS)
    if parsed_url.scheme() != "http" && parsed_url.scheme() != "https" {
        return Err("Only HTTP and HTTPS schemes are allowed".to_string());
    }

    let host = parsed_url.host_str().ok_or("URL must have a host")?;
    let port = parsed_url.port_or_known_default().unwrap_or(80);

    // 2. Perform DNS resolution to prevent rebinding or obfuscation bypasses
    let addr_str = format!("{}:{}", host, port);
    let mut addrs = addr_str.to_socket_addrs().map_err(|e| format!("DNS resolution failed: {}", e))?;

    // 3. Verify that ALL resolved IP addresses are safe public IPs
    let mut resolved_any = false;
    for addr in addrs {
        resolved_any = true;
        let ip = addr.ip();
        if is_internal_ip(&ip) {
            return Err(format!("SSRF blocked: Host resolves to a private or internal IP ({})", ip));
        }
    }

    if !resolved_any {
        return Err("Could not resolve host to any IP addresses".to_string());
    }

    Ok(parsed_url)
}

fn is_internal_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            ipv4.is_loopback() ||
            ipv4.is_private() ||
            ipv4.is_link_local() ||
            ipv4.is_broadcast() ||
            ipv4.is_documentation() ||
            ipv4.is_unspecified()
        },
        IpAddr::V6(ipv6) => {
            ipv6.is_loopback() ||
            ipv6.is_unspecified() ||
            (ipv6.segments()[0] & 0xffc0) == 0xfe80 // Link-local
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_public_url() {
        let result = validate_url_safe("https://google.com");
        assert!(result.is_ok());
    }

    #[test]
    fn test_ssrf_loopback() {
        let result = validate_url_safe("http://127.0.0.1:8080/admin");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("SSRF blocked"));

        let result2 = validate_url_safe("http://localhost/admin");
        assert!(result2.is_err());
    }

    #[test]
    fn test_ssrf_aws_metadata() {
        let result = validate_url_safe("http://169.254.169.254/latest/meta-data/");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("SSRF blocked"));
    }

    #[test]
    fn test_ssrf_private_network() {
        let result = validate_url_safe("http://192.168.1.1/router_admin");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("SSRF blocked"));
    }

    #[test]
    fn test_invalid_scheme() {
        let result = validate_url_safe("file:///etc/passwd");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Only HTTP and HTTPS"));
    }
}
