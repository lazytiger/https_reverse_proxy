use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Cursor, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CertificateSigningRequest, DistinguishedName,
    DnType, IsCa, KeyPair, KeyUsagePurpose, SanType,
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
    store_path: PathBuf,
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
    pub fn new(crt: String, key: String, store_path: String) -> Result<Self> {
        let ca_crt = std::io::read_to_string(&mut BufReader::new(File::open(crt)?))?;
        let ca_key = std::io::read_to_string(&mut BufReader::new(File::open(key)?))?;
        let key = KeyPair::from_pem(ca_key.as_str())?;
        let params = CertificateParams::from_ca_cert_pem(ca_crt.as_str(), key)?;
        let root_ca = Certificate::from_params(params)?;
        let ca_crt = root_ca.serialize_pem()?;

        Ok(Self {
            ca_crt,
            root_ca,
            store_path: store_path.into(),
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
        let key = unsigned.serialize_private_key_pem();
        self.save(name, signed_pem.clone(), key.clone())?;
        self.extract_certificate_key(signed_pem, key)
    }

    fn extract_certificate_key(&self, crt: String, key: String) -> Result<CertifiedKey> {
        let crt = crt + self.ca_crt.as_str();
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

    fn get_path_and_name(&self, name: &str) -> (PathBuf, PathBuf) {
        let data = md5::compute(name);
        let name = format!("{:x}", data);
        let dir = &name[0..2];
        let file = &name[2..];
        log::info!("{} - {}, {}", name, dir, file);
        (dir.into(), file.into())
    }

    fn save(&self, name: &str, crt: String, key: String) -> Result<()> {
        let cert_store = self.store_path.join("certs");
        let key_store = self.store_path.join("keys");
        let (dir, file) = self.get_path_and_name(name);
        let cert_file = cert_store.join(dir.clone()).join(file.clone());
        std::fs::create_dir_all(cert_file.parent().unwrap())?;
        let key_file = key_store.join(dir).join(file);
        std::fs::create_dir_all(key_file.parent().unwrap())?;
        let mut file = File::create(cert_file)?;
        file.write_all(crt.as_bytes())?;
        let mut file = File::create(key_file)?;
        file.write_all(key.as_bytes())?;
        Ok(())
    }

    fn load(&self, name: &str) -> Result<CertifiedKey> {
        let cert_store = self.store_path.join("certs");
        let key_store = self.store_path.join("keys");
        let (dir, file) = self.get_path_and_name(name);
        let cert_file = cert_store.join(dir.clone()).join(file.clone());
        let key_file = key_store.join(dir).join(file);
        let file = File::open(cert_file)?;
        let crt = std::io::read_to_string(file)?;
        let file = File::open(key_file)?;
        let key = std::io::read_to_string(file)?;
        self.extract_certificate_key(crt, key)
    }
}

impl ResolvesServerCert for DynamicCertificateResolver {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        let name = client_hello.server_name()?.to_string();
        let certs = self.certs.lock().ok()?;
        let ck = if let Some(ck) = certs.get(&name) {
            ck.clone()
        } else {
            drop(certs);
            let ck = if let Ok(ck) = self.load(name.as_str()) {
                ck
            } else {
                self.sign(name.as_str()).ok()?
            };
            let ck = Arc::new(ck);
            let mut certs = self.certs.lock().ok()?;
            certs.insert(name, ck.clone());
            ck
        };
        Some(ck)
    }
}
