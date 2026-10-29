//! The per-session certificate authority and the trust bundle given to the
//! child.

use super::*;

pub(super) struct CertificateAuthority {
    pub(super) certificate: Certificate,
    pub(super) issuer: Issuer<'static, KeyPair>,
}

impl CertificateAuthority {
    pub(super) fn new() -> Result<Self> {
        let mut params = CertificateParams::new(Vec::<String>::new())
            .map_err(|error| proxy_error(format!("failed to configure CA: {error}")))?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "fnox proxy session");
        let key = KeyPair::generate()
            .map_err(|error| proxy_error(format!("failed to generate CA key: {error}")))?;
        let certificate = params
            .self_signed(&key)
            .map_err(|error| proxy_error(format!("failed to generate CA certificate: {error}")))?;
        Ok(Self {
            certificate,
            issuer: Issuer::new(params, key),
        })
    }

    pub(super) fn server_config(&self, domain: &str) -> Result<ServerConfig> {
        let params = CertificateParams::new(vec![domain.to_string()]).map_err(|error| {
            proxy_error(format!("failed to configure TLS certificate: {error}"))
        })?;
        let key = KeyPair::generate()
            .map_err(|error| proxy_error(format!("failed to generate TLS key: {error}")))?;
        let certificate = params
            .signed_by(&key, &self.issuer)
            .map_err(|error| proxy_error(format!("failed to sign TLS certificate: {error}")))?;
        let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate.der().clone()], private_key)
            .map_err(|error| proxy_error(format!("failed to configure TLS: {error}")))?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(config)
    }
}

pub(super) fn write_trust_bundle(file: &mut impl Write, authority: &Certificate) -> Result<()> {
    let native = rustls_native_certs::load_native_certs();
    if native.certs.is_empty() {
        return Err(proxy_error(format!(
            "failed to load native TLS roots for proxy trust bundle{}",
            native
                .errors
                .first()
                .map(|error| format!(": {error}"))
                .unwrap_or_default()
        )));
    }
    for error in native.errors {
        tracing::warn!("failed to load a native TLS root: {error}");
    }
    for certificate in native.certs {
        write_pem_certificate(file, certificate.as_ref())
            .map_err(|error| proxy_error(format!("failed to write native CA: {error}")))?;
    }
    file.write_all(authority.pem().as_bytes())
        .map_err(|error| proxy_error(format!("failed to write proxy CA: {error}")))
}

pub(super) fn write_pem_certificate(file: &mut impl Write, der: &[u8]) -> std::io::Result<()> {
    writeln!(file, "-----BEGIN CERTIFICATE-----")?;
    let encoded = base64::engine::general_purpose::STANDARD.encode(der);
    for line in encoded.as_bytes().chunks(64) {
        file.write_all(line)?;
        file.write_all(b"\n")?;
    }
    writeln!(file, "-----END CERTIFICATE-----")
}
