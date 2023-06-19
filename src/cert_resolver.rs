use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Cursor};
use std::sync::{Arc, Mutex};

use rcgen::{BasicConstraints, Certificate, CertificateParams, IsCa, KeyPair, SanType};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::PrivateKey;
use rustls_pemfile::Item;

use crate::types::{Error, Result};

pub struct DynamicCertificateResolver {
    ca_crt: String,
    ca_key: String,
    certs: Mutex<HashMap<String, Arc<CertifiedKey>>>,
}

impl DynamicCertificateResolver {
    pub fn new(crt: String, key: String) -> Result<Self> {
        let ca_crt = std::io::read_to_string(&mut BufReader::new(File::open(crt)?))?;
        pem::parse(ca_crt.as_str()).unwrap();
        let ca_key = std::io::read_to_string(&mut BufReader::new(File::open(key)?))?;
        Ok(Self {
            ca_key,
            ca_crt,
            certs: Default::default(),
        })
    }

    fn sign(&self, name: &str) -> Result<CertifiedKey> {
        let key = KeyPair::from_pem(self.ca_key.as_str())?;
        pem::parse(self.ca_crt.as_str()).unwrap();
        let mut params = CertificateParams::from_ca_cert_pem(self.ca_crt.as_str(), key)?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.subject_alt_names = vec![SanType::DnsName(name.to_string())];
        let signer = Certificate::from_params(params)?;
        let crt = signer.serialize_pem()?;
        let key = signer.serialize_private_key_pem();
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
            .map(|key| rustls::sign::any_supported_type(&key))
            .nth(0)
            .ok_or(Error::PrivateKeyNotFound)??;
        Ok(CertifiedKey::new(certs, key))
    }
}

impl ResolvesServerCert for DynamicCertificateResolver {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        println!("resolve now");
        let name = client_hello.server_name()?.to_string();
        println!("resolve {} now", name);
        let certs = self.certs.lock().ok()?;
        let ck = if let Some(ck) = certs.get(&name) {
            ck.clone()
        } else {
            drop(certs);
            println!("{} not found, signing now", name);
            let ret = self.sign(name.as_str());
            if let Err(err) = &ret {
                println!("sign failed:{:?}", err);
            }
            let ck = Arc::new(ret.ok()?);
            let mut certs = self.certs.lock().ok()?;
            certs.insert(name, ck.clone());
            //TODO save ck into files
            println!("sign ok");
            ck
        };
        Some(ck)
    }
}
