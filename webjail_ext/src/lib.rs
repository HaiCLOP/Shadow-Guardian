use pyo3::prelude::*;
use pyo3::exceptions::PyIOError;
use std::fs::{self, File};
use std::io::{Write};
use std::path::Path;
use std::process::Command;
use tempfile::NamedTempFile;

const MARKER_START: &str = "# >>> ShadowGuardian WebJail START >>>";
const MARKER_END: &str = "# <<< ShadowGuardian WebJail END <<<";

/// Build the managed hosts entries block.
#[pyfunction]
fn build_managed_section(mut domains: Vec<String>) -> String {
    if domains.is_empty() {
        return String::new();
    }

    let doh_providers = vec![
        "cloudflare-dns.com",
        "mozilla.cloudflare-dns.com",
        "dns.google",
        "dns.quad9.net",
        "doh.opendns.com",
        "dns.adguard.com",
        "dns.nextdns.io",
    ];

    for p in doh_providers {
        if !domains.contains(&p.to_string()) {
            domains.push(p.to_string());
        }
    }

    domains.sort();

    let mut section = String::new();
    section.push_str(MARKER_START);
    section.push_str("\n");

    for domain in domains {
        section.push_str(&format!("0.0.0.0 {}\n", domain));
        section.push_str(&format!(":: {}\n", domain));
        if !domain.starts_with("www.") {
            section.push_str(&format!("0.0.0.0 www.{}\n", domain));
            section.push_str(&format!(":: www.{}\n", domain));
        }
    }

    section.push_str(MARKER_END);
    section.push_str("\n");
    section
}

/// Remove any existing ShadowGuardian-managed section.
#[pyfunction]
fn strip_managed_section(content: &str) -> String {
    let mut result = String::new();
    let mut in_managed = false;

    // We split by lines but keep the newlines. However, str::lines() removes them.
    // Let's iterate and reconstruct with \n. We'll handle \r\n properly.
    let mut lines = content.lines().peekable();
    while let Some(line) = lines.next() {
        if line.contains(MARKER_START) {
            in_managed = true;
            continue;
        }
        if line.contains(MARKER_END) {
            in_managed = false;
            continue;
        }
        if !in_managed {
            result.push_str(line);
            result.push('\n');
        }
    }
    result
}

/// Write content to hosts file atomically using tempfile.
#[pyfunction]
fn write_hosts(content: &str, hosts_path: &str) -> PyResult<bool> {
    let path = Path::new(hosts_path);
    let dir = path.parent().unwrap_or(Path::new("."));
    
    // Create a temp file in the same directory for atomic rename
    match NamedTempFile::new_in(dir) {
        Ok(mut temp) => {
            if let Err(_) = temp.write_all(content.as_bytes()) {
                return Ok(false);
            }
            if let Err(_) = temp.flush() {
                return Ok(false);
            }
            
            // Persist the tempfile to the target path
            if let Err(_) = temp.persist(path) {
                // os.replace fallback
                if let Err(_) = fs::write(path, content.as_bytes()) {
                    return Ok(false);
                }
            }
            
            // Verify write
            if let Ok(written) = fs::read_to_string(path) {
                if content.contains(MARKER_START) && !written.contains(MARKER_START) {
                    return Ok(false);
                }
            }
            
            Ok(true)
        }
        Err(_) => {
            // Fallback to direct write
            match fs::write(path, content.as_bytes()) {
                Ok(_) => Ok(true),
                Err(_) => Ok(false)
            }
        }
    }
}

/// Flush the Windows DNS resolver cache.
#[pyfunction]
fn flush_dns() -> PyResult<()> {
    // CREATE_NO_WINDOW = 0x08000000
    use std::os::windows::process::CommandExt;
    
    // Attempt ipconfig.exe
    let mut cmd = Command::new("ipconfig.exe");
    cmd.arg("/flushdns")
       .creation_flags(0x08000000);
       
    if let Err(_) = cmd.output() {
        // Fallback without .exe
        let _ = Command::new("ipconfig")
            .arg("/flushdns")
            .creation_flags(0x08000000)
            .output();
    }
    
    Ok(())
}

/// A Python module implemented in Rust.
#[pymodule]
fn webjail_ext(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(build_managed_section, m)?)?;
    m.add_function(wrap_pyfunction!(strip_managed_section, m)?)?;
    m.add_function(wrap_pyfunction!(write_hosts, m)?)?;
    m.add_function(wrap_pyfunction!(flush_dns, m)?)?;
    Ok(())
}
