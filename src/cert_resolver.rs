use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Cursor};
use std::sync::{Arc, Mutex};

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CertificateSigningRequest, DistinguishedName,
    DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, SanType,
};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::PrivateKey;
use rustls_pemfile::Item;

use crate::types::{Error, Result};

pub struct DynamicCertificateResolver {
    ca_crt: String,
    root_ca: Certificate,
    certs: Mutex<HashMap<String, Arc<CertifiedKey>>>,
}

pub fn gen_root_ca() -> Result<(String, String)> {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CountryName, "CN");
    dn.push(DnType::CommonName, "Auto-Generated CA");

    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
    params.distinguished_name = dn;
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let root_ca = Certificate::from_params(params)?;

    Ok((
        root_ca.serialize_pem()?,
        root_ca.serialize_private_key_pem(),
    ))
}

impl DynamicCertificateResolver {
    pub fn new(crt: String, key: String) -> Result<Self> {
        let ca_crt = std::io::read_to_string(&mut BufReader::new(File::open(crt)?))?;
        let ca_key = std::io::read_to_string(&mut BufReader::new(File::open(key)?))?;
        let key = KeyPair::from_pem(ca_key.as_str())?;
        let params = CertificateParams::from_ca_cert_pem(ca_crt.as_str(), key)?;
        log::info!(
            "key usage:{:?}, is_ca:{:?}, alg:{:?}, dn:{:?}",
            params.key_usages,
            params.is_ca,
            params.alg,
            params.distinguished_name
        );
        let root_ca = Certificate::from_params(params)?;
        let ca_crt = root_ca.serialize_pem()?;

        Ok(Self {
            ca_crt,
            root_ca,
            certs: Default::default(),
        })
    }

    fn sign(&self, name: &str) -> Result<CertifiedKey> {
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CountryName, "CN");
        dn.push(DnType::CommonName, "Auto-Generated Server");

        let mut params = CertificateParams::default();
        params.is_ca = IsCa::NoCa;
        params.alg = self.root_ca.get_params().alg;
        params.distinguished_name = dn;
        params.subject_alt_names = vec![SanType::DnsName(name.into())];

        let unsigned = Certificate::from_params(params)?;
        let request_pem = unsigned.serialize_request_pem()?;
        let csr = CertificateSigningRequest::from_pem(&request_pem)?;
        let signed_pem = csr.serialize_pem_with_signer(&self.root_ca)?;
        let crt = signed_pem + self.ca_crt.as_str();
        let key = unsigned.serialize_private_key_pem();
        log::info!("{}", crt);
        log::info!("{}", key);
        let certs = rustls_pemfile::certs(&mut Cursor::new(crt.as_bytes()))?
            .into_iter()
            .map(|cert| rustls::Certificate(cert))
            .collect();
        let key = rustls_pemfile::read_all(&mut Cursor::new(key.as_bytes()))?
            .into_iter()
            .map(|item| match item {
                Item::RSAKey(key) => key,
                Item::PKCS8Key(key) => key,
                Item::ECKey(key) => key,
                _ => unreachable!(),
            })
            .map(PrivateKey)
            .filter_map(|key| rustls::sign::any_supported_type(&key).ok())
            .nth(0)
            .ok_or(Error::PrivateKeyNotFound)?;
        Ok(CertifiedKey::new(certs, key))
    }
}

impl ResolvesServerCert for DynamicCertificateResolver {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        let name = client_hello.server_name()?.to_string();
        log::info!("try resolve {} certificate", name);
        let certs = self.certs.lock().ok()?;
        let ck = if let Some(ck) = certs.get(&name) {
            ck.clone()
        } else {
            drop(certs);
            let ret = self.sign(name.as_str());
            if let Err(err) = &ret {
                log::info!("sign failed:{:?}", err);
            }
            let ck = Arc::new(ret.ok()?);
            let mut certs = self.certs.lock().ok()?;
            certs.insert(name, ck.clone());
            //TODO save ck into files
            ck
        };
        Some(ck)
    }
}
