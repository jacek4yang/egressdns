//! Shared TLS configuration.
//!
//! There is deliberately no switch anywhere in this crate that disables certificate
//! verification. Probes that need to inspect a certificate use [`CapturingVerifier`],
//! which delegates every decision to the real WebPKI verifier and merely records the leaf
//! certificate afterwards.

use std::path::Path;
use std::sync::Arc;

use parking_lot::Mutex;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, DigitallySignedStruct, Error as TlsError, RootCertStore, SignatureScheme,
};

/// Errors while assembling a TLS configuration.
#[derive(Debug, thiserror::Error)]
pub enum TlsConfigError {
    /// A CA bundle could not be read.
    #[error("cannot read CA bundle {path}: {source}")]
    Read {
        /// Offending path.
        path: String,
        /// Underlying error.
        #[source]
        source: std::io::Error,
    },
    /// A CA bundle contained no usable certificates.
    #[error("CA bundle {0} contained no certificates")]
    Empty(String),
    /// A CA bundle was readable but not valid PEM.
    #[error("CA bundle {path} is not valid PEM: {detail}")]
    Pem {
        /// Offending path.
        path: String,
        /// What the PEM parser objected to.
        detail: String,
    },
    /// rustls rejected the assembled configuration.
    #[error("tls configuration rejected: {0}")]
    Rustls(#[from] TlsError),
    /// The verifier could not be constructed.
    #[error("certificate verifier could not be built: {0}")]
    Verifier(String),
}

/// Build a root certificate store.
///
/// The compiled-in Mozilla root set is always included so that the daemon still works when
/// the platform store is missing, which matters under a hardened systemd unit with
/// `ProtectSystem=strict`.
pub fn root_store(
    use_system_roots: bool,
    extra_ca_files: &[std::path::PathBuf],
) -> Result<RootCertStore, TlsConfigError> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    if use_system_roots {
        let loaded = rustls_native_certs::load_native_certs();
        for cert in loaded.certs {
            // Individual platform certificates are allowed to fail; the Mozilla set is
            // already present.
            let _ = roots.add(cert);
        }
    }

    for path in extra_ca_files {
        let added = add_pem_bundle(&mut roots, path)?;
        if added == 0 {
            return Err(TlsConfigError::Empty(path.display().to_string()));
        }
    }
    Ok(roots)
}

fn add_pem_bundle(roots: &mut RootCertStore, path: &Path) -> Result<usize, TlsConfigError> {
    let data = std::fs::read(path).map_err(|source| TlsConfigError::Read {
        path: path.display().to_string(),
        source,
    })?;
    // PEM parsing comes from rustls-pki-types directly. The rustls-pemfile crate is a thin
    // wrapper around this same code and was archived upstream in 2025 (RUSTSEC-2025-0134),
    // so depending on the wrapper would mean carrying an unmaintained crate for no benefit.
    let mut added = 0usize;
    for cert in CertificateDer::pem_slice_iter(&data) {
        let cert = cert.map_err(|source| TlsConfigError::Pem {
            path: path.display().to_string(),
            detail: source.to_string(),
        })?;
        if roots.add(cert).is_ok() {
            added += 1;
        }
    }
    Ok(added)
}

/// Install the process-wide rustls crypto provider. Safe to call repeatedly.
pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Build a client configuration with the given ALPN protocols.
pub fn client_config(
    roots: Arc<RootCertStore>,
    alpn: &[&str],
    enable_resumption: bool,
) -> ClientConfig {
    let mut cfg = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = alpn.iter().map(|p| p.as_bytes().to_vec()).collect();
    if !enable_resumption {
        cfg.resumption = rustls::client::Resumption::disabled();
    }
    // 0-RTT / early data is never offered: DNS queries are not safe to replay, and the
    // security analysis in docs/THREAT_MODEL.md concludes the latency saving is not worth
    // the replay exposure.
    cfg.enable_early_data = false;
    cfg
}

/// Build a client configuration that also captures the peer certificate chain.
pub fn capturing_client_config(
    roots: Arc<RootCertStore>,
    alpn: &[&str],
) -> Result<(ClientConfig, Arc<CapturedChain>), TlsConfigError> {
    let inner = WebPkiServerVerifier::builder(roots.clone())
        .build()
        .map_err(|e| TlsConfigError::Verifier(e.to_string()))?;
    let captured = Arc::new(CapturedChain::default());
    let verifier = Arc::new(CapturingVerifier {
        inner,
        captured: Arc::clone(&captured),
    });
    let mut cfg = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = alpn.iter().map(|p| p.as_bytes().to_vec()).collect();
    cfg.enable_early_data = false;
    cfg.dangerous().set_certificate_verifier(verifier);
    Ok((cfg, captured))
}

/// Recorded leaf certificate facts.
#[derive(Debug, Default)]
pub struct CapturedChain {
    inner: Mutex<Option<CapturedLeaf>>,
}

/// Facts extracted from a successfully verified leaf certificate.
#[derive(Debug, Clone)]
pub struct CapturedLeaf {
    /// SHA-256 of the DER SubjectPublicKeyInfo.
    pub spki_sha256: Option<[u8; 32]>,
    /// Issuer common name.
    pub issuer_cn: Option<String>,
}

impl CapturedChain {
    /// Read the captured leaf, if the handshake got far enough to verify one.
    pub fn leaf(&self) -> Option<CapturedLeaf> {
        self.inner.lock().clone()
    }
}

/// A verifier that delegates to the real WebPKI verifier and records the leaf.
///
/// This exists only so that probe validation profiles can assert SPKI pins and issuer
/// constraints. It never weakens verification: every method forwards to `inner` and
/// returns whatever `inner` decided.
#[derive(Debug)]
pub struct CapturingVerifier {
    inner: Arc<WebPkiServerVerifier>,
    captured: Arc<CapturedChain>,
}

impl ServerCertVerifier for CapturingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        let verified = self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;
        let leaf = CapturedLeaf {
            spki_sha256: crate::util::der::spki_sha256(end_entity.as_ref()),
            issuer_cn: crate::util::der::issuer_common_name(end_entity.as_ref()),
        };
        *self.captured.inner.lock() = Some(leaf);
        Ok(verified)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiled_in_roots_are_present() {
        install_crypto_provider();
        let roots = root_store(false, &[]).expect("roots");
        assert!(
            roots.len() > 50,
            "expected the Mozilla root set, got {}",
            roots.len()
        );
    }

    #[test]
    fn extra_ca_bundle_is_loaded() {
        install_crypto_provider();
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("ca.pem");
        let key = rcgen::KeyPair::generate().expect("key");
        let mut params =
            rcgen::CertificateParams::new(vec!["test-ca".to_string()]).expect("params");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let cert = params.self_signed(&key).expect("cert");
        std::fs::write(&path, cert.pem()).expect("write");
        let before = root_store(false, &[]).expect("roots").len();
        let after = root_store(false, &[path]).expect("roots").len();
        assert_eq!(after, before + 1);
    }

    #[test]
    fn empty_bundle_is_rejected() {
        install_crypto_provider();
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("empty.pem");
        std::fs::write(&path, b"not a certificate\n").expect("write");
        assert!(matches!(
            root_store(false, &[path]),
            Err(TlsConfigError::Empty(_))
        ));
    }

    #[test]
    fn client_config_never_enables_early_data() {
        install_crypto_provider();
        let roots = Arc::new(root_store(false, &[]).expect("roots"));
        let cfg = client_config(roots, &["h2"], true);
        assert!(!cfg.enable_early_data);
        assert_eq!(cfg.alpn_protocols, vec![b"h2".to_vec()]);
    }

    #[test]
    fn capturing_config_builds() {
        install_crypto_provider();
        let roots = Arc::new(root_store(false, &[]).expect("roots"));
        let (cfg, captured) =
            capturing_client_config(roots, &["h2", "http/1.1"]).expect("capturing config");
        assert!(!cfg.enable_early_data);
        assert!(captured.leaf().is_none());
    }
}
