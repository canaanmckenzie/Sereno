//! Code signature verification using Windows WinVerifyTrust API
//!
//! This module verifies Authenticode signatures on Windows executables,
//! similar to how Little Snitch shows signing status.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Signature verification result
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureStatus {
    /// Signed and verified (includes signer name)
    Signed { signer: String },
    /// Not signed
    Unsigned,
    /// Signature is invalid or tampered
    Invalid,
    /// Could not verify (file not found, access denied, etc.)
    Unknown,
}

impl SignatureStatus {
    /// Short label for TUI display
    pub fn short_label(&self) -> &str {
        match self {
            SignatureStatus::Signed { .. } => "Signed",
            SignatureStatus::Unsigned => "No Sig",
            SignatureStatus::Invalid => "Bad!",
            SignatureStatus::Unknown => "?",
        }
    }

    /// Get signer name if signed
    pub fn signer(&self) -> Option<&str> {
        match self {
            SignatureStatus::Signed { signer } => Some(signer),
            _ => None,
        }
    }
}

/// Cache for signature verification results
pub struct SignatureCache {
    cache: Arc<RwLock<HashMap<String, SignatureStatus>>>,
}

impl SignatureCache {
    pub fn new() -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get cached signature status or verify and cache
    pub fn get_or_verify(&self, path: &str) -> SignatureStatus {
        // Normalize path for cache lookup
        let cache_key = path.to_lowercase();

        // Check cache first
        if let Ok(cache) = self.cache.read() {
            if let Some(status) = cache.get(&cache_key) {
                return status.clone();
            }
        }

        // Verify and cache
        let status = verify_signature(path);
        if let Ok(mut cache) = self.cache.write() {
            // Limit cache size to prevent memory growth
            if cache.len() > 1000 {
                cache.clear();
            }
            cache.insert(cache_key, status.clone());
        }

        status
    }
}

impl Default for SignatureCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert NT device path to DOS path (e.g., \Device\HarddiskVolume3\... -> C:\...)
#[cfg(windows)]
fn nt_path_to_dos_path(nt_path: &str) -> Option<String> {
    use windows::Win32::Storage::FileSystem::QueryDosDeviceW;

    // Check if it's already a DOS path
    if nt_path.len() >= 2 && nt_path.chars().nth(1) == Some(':') {
        return Some(nt_path.to_string());
    }

    // Must start with \Device\
    if !nt_path.starts_with("\\Device\\") {
        return None;
    }

    // Try each drive letter A-Z
    for letter in b'A'..=b'Z' {
        let drive = format!("{}:", letter as char);
        let wide_drive: Vec<u16> = drive.encode_utf16().chain(std::iter::once(0)).collect();

        let mut buffer = vec![0u16; 260];
        let len = unsafe {
            QueryDosDeviceW(
                windows::core::PCWSTR(wide_drive.as_ptr()),
                Some(&mut buffer),
            )
        };

        if len > 0 {
            // Find the null terminator
            let device_path = String::from_utf16_lossy(
                &buffer[..buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len())]
            );

            // Check if NT path starts with this device path
            if nt_path.starts_with(&device_path) {
                let remainder = &nt_path[device_path.len()..];
                return Some(format!("{}{}", drive, remainder));
            }
        }
    }

    None
}

/// Verify the Authenticode signature of a Windows executable using WinVerifyTrust
#[cfg(windows)]
pub fn verify_signature(path: &str) -> SignatureStatus {
    use std::path::Path;

    // Convert NT device path to DOS path if needed
    let dos_path = nt_path_to_dos_path(path).unwrap_or_else(|| path.to_string());

    // Check if file exists first
    if !Path::new(&dos_path).exists() {
        return SignatureStatus::Unknown;
    }

    // Try WinVerifyTrust
    match win_verify_trust(&dos_path) {
        Ok(status) => status,
        Err(_) => SignatureStatus::Unknown,
    }
}

#[cfg(windows)]
fn win_verify_trust(path: &str) -> Result<SignatureStatus, ()> {
    use std::mem::{size_of, zeroed};
    use std::ptr::null_mut;
    use windows::core::PWSTR;
    use windows::Win32::Foundation::HWND;
    use windows::Win32::Security::WinTrust::{
        WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA,
        WINTRUST_DATA_0, WINTRUST_DATA_PROVIDER_FLAGS, WINTRUST_DATA_UICONTEXT,
        WINTRUST_FILE_INFO, WTD_CHOICE_FILE, WTD_REVOKE_NONE,
        WTD_STATEACTION_VERIFY, WTD_UI_NONE,
    };

    // Convert path to wide string
    let wide_path: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();

    // Set up WINTRUST_FILE_INFO
    let mut file_info: WINTRUST_FILE_INFO = unsafe { zeroed() };
    file_info.cbStruct = size_of::<WINTRUST_FILE_INFO>() as u32;
    file_info.pcwszFilePath = windows::core::PCWSTR(wide_path.as_ptr());

    // Set up WINTRUST_DATA
    let mut trust_data: WINTRUST_DATA = unsafe { zeroed() };
    trust_data.cbStruct = size_of::<WINTRUST_DATA>() as u32;
    trust_data.dwUIChoice = WTD_UI_NONE;
    trust_data.fdwRevocationChecks = WTD_REVOKE_NONE;
    trust_data.dwUnionChoice = WTD_CHOICE_FILE;
    trust_data.Anonymous = WINTRUST_DATA_0 {
        pFile: &mut file_info,
    };
    trust_data.dwStateAction = WTD_STATEACTION_VERIFY;
    trust_data.dwProvFlags = WINTRUST_DATA_PROVIDER_FLAGS(0);
    trust_data.dwUIContext = WINTRUST_DATA_UICONTEXT(0);
    trust_data.pwszURLReference = PWSTR(null_mut());

    // WINTRUST_ACTION_GENERIC_VERIFY_V2 GUID
    let mut action_guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    // Call WinVerifyTrust
    // NULL hwnd means no UI
    let result = unsafe {
        WinVerifyTrust(
            HWND(std::ptr::null_mut()),
            &mut action_guid,
            &mut trust_data as *mut _ as *mut _,
        )
    };

    // Interpret result
    // 0 = Success (signed and valid)
    // TRUST_E_NOSIGNATURE (0x800B0100) = Not signed
    // TRUST_E_BAD_DIGEST (0x80096010) = Signature invalid
    const TRUST_E_NOSIGNATURE: i32 = 0x800B0100u32 as i32;
    const TRUST_E_EXPLICIT_DISTRUST: i32 = 0x800B0111u32 as i32;
    const TRUST_E_SUBJECT_NOT_TRUSTED: i32 = 0x800B0004u32 as i32;
    const CRYPT_E_SECURITY_SETTINGS: i32 = 0x80092026u32 as i32;

    let status = if result == 0 {
        // Signature valid - get signer name
        let signer = get_signer_name(path).unwrap_or_else(|| "Verified".to_string());
        SignatureStatus::Signed { signer }
    } else if result == TRUST_E_NOSIGNATURE {
        SignatureStatus::Unsigned
    } else if result == TRUST_E_EXPLICIT_DISTRUST
           || result == TRUST_E_SUBJECT_NOT_TRUSTED
           || result == CRYPT_E_SECURITY_SETTINGS {
        SignatureStatus::Invalid
    } else {
        // Other errors - check if file has embedded signature at all
        // 0x800B0101 = TRUST_E_BAD_DIGEST (tampered)
        // 0x800B010A = CERT_E_CHAINING (cert chain issue)
        SignatureStatus::Invalid
    };

    Ok(status)
}

/// Extract signer name from certificate using CryptQueryObject
#[cfg(windows)]
fn get_signer_name(path: &str) -> Option<String> {
    use std::ffi::c_void;
    use std::ptr::null_mut;
    use windows::Win32::Security::Cryptography::{
        CertCloseStore, CertFindCertificateInStore, CertFreeCertificateContext,
        CertGetNameStringW, CryptQueryObject,
        CERT_FIND_SUBJECT_CERT, CERT_NAME_SIMPLE_DISPLAY_TYPE,
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, CERT_QUERY_CONTENT_TYPE,
        CERT_QUERY_ENCODING_TYPE, CERT_QUERY_FORMAT_FLAG_BINARY,
        CERT_QUERY_FORMAT_TYPE, CERT_QUERY_OBJECT_FILE, HCERTSTORE,
    };

    let wide_path: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();

    let mut encoding = CERT_QUERY_ENCODING_TYPE(0);
    let mut content_type = CERT_QUERY_CONTENT_TYPE(0);
    let mut format_type = CERT_QUERY_FORMAT_TYPE(0);
    let mut cert_store: HCERTSTORE = HCERTSTORE(null_mut());
    // Use raw pointer for msg since HCRYPTMSG may not be available
    let mut msg: *mut c_void = null_mut();

    // Query the object to get the cert store (we skip the message handle for signer extraction)
    let result = unsafe {
        CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            wide_path.as_ptr() as *const _,
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            Some(&mut encoding as *mut CERT_QUERY_ENCODING_TYPE),
            Some(&mut content_type as *mut CERT_QUERY_CONTENT_TYPE),
            Some(&mut format_type as *mut CERT_QUERY_FORMAT_TYPE),
            Some(&mut cert_store),
            None, // Skip message handle
            None,
        )
    };

    if result.is_err() {
        return None;
    }

    // Get the first certificate from the store (usually the signer cert)
    let cert_context = unsafe {
        CertFindCertificateInStore(
            cert_store,
            encoding,
            0,
            windows::Win32::Security::Cryptography::CERT_FIND_ANY,
            None,
            None,
        )
    };

    if cert_context.is_null() {
        unsafe {
            if !cert_store.0.is_null() {
                let _ = CertCloseStore(cert_store, 0);
            }
        }
        return None;
    }

    // Get the subject name from certificate
    let mut name_buffer = vec![0u16; 256];
    let name_len = unsafe {
        CertGetNameStringW(
            cert_context,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            None,
            Some(&mut name_buffer),
        )
    };

    // Clean up
    unsafe {
        let _ = CertFreeCertificateContext(Some(cert_context));
        if !cert_store.0.is_null() {
            let _ = CertCloseStore(cert_store, 0);
        }
    }

    if name_len > 1 {
        // Convert wide string to String, excluding null terminator
        let name = String::from_utf16_lossy(&name_buffer[..(name_len - 1) as usize]);
        // Shorten common long names
        let short_name = shorten_signer_name(&name);
        Some(short_name)
    } else {
        None
    }
}

/// Shorten common long signer names for TUI display
fn shorten_signer_name(name: &str) -> String {
    // Common shortenings for readability
    if name.contains("Microsoft") {
        return "Microsoft".to_string();
    }
    if name.contains("Google") {
        return "Google".to_string();
    }
    if name.contains("Mozilla") {
        return "Mozilla".to_string();
    }
    if name.contains("Apple") {
        return "Apple".to_string();
    }
    if name.contains("Adobe") {
        return "Adobe".to_string();
    }
    if name.contains("NVIDIA") {
        return "NVIDIA".to_string();
    }
    if name.contains("Intel") {
        return "Intel".to_string();
    }
    if name.contains("AMD") || name.contains("Advanced Micro") {
        return "AMD".to_string();
    }
    if name.contains("Valve") {
        return "Valve".to_string();
    }
    if name.contains("Discord") {
        return "Discord".to_string();
    }
    if name.contains("Slack") {
        return "Slack".to_string();
    }
    if name.contains("Zoom") {
        return "Zoom".to_string();
    }
    if name.contains("Node.js") || name.contains("OpenJS") {
        return "Node.js".to_string();
    }
    if name.contains("Oracle") {
        return "Oracle".to_string();
    }
    if name.contains("Amazon") {
        return "Amazon".to_string();
    }
    if name.contains("Anthropic") {
        return "Anthropic".to_string();
    }

    // Truncate long names
    if name.len() > 20 {
        format!("{}...", &name[..17])
    } else {
        name.to_string()
    }
}

/// Non-Windows stub
#[cfg(not(windows))]
pub fn verify_signature(_path: &str) -> SignatureStatus {
    SignatureStatus::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_cache() {
        let cache = SignatureCache::new();
        // First call should verify
        let status1 = cache.get_or_verify("C:\\Windows\\System32\\notepad.exe");
        // Second call should use cache
        let status2 = cache.get_or_verify("C:\\Windows\\System32\\notepad.exe");
        assert_eq!(status1, status2);
    }

    #[test]
    fn test_shorten_signer_name() {
        assert_eq!(shorten_signer_name("Microsoft Corporation"), "Microsoft");
        assert_eq!(shorten_signer_name("Google LLC"), "Google");
        assert_eq!(shorten_signer_name("Some Very Long Company Name Inc."), "Some Very Long Co...");
    }
}
