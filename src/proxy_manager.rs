use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use mio::Registry;

use crate::dns_resolver::DnsResolver;
use crate::proxy_conn::ProxyConnection;
use crate::tls_conn::TlsStream;

pub struct ProxyManager {
    proxies: HashMap<usize, ProxyConnection<TlsStream>>,
    to_removed: HashSet<usize>,
}

impl ProxyManager {
    pub fn dispatch(&mut self, index: usize, registry: &Registry, dns_resolver: &mut DnsResolver) {
        let mut close = false;
        if let Some(conn) = self.proxies.get_mut(&index) {
            conn.tick(registry, dns_resolver);
            close = conn.is_safe_to_close();
        }
        if close {
            self.to_removed.insert(index);
        }
    }

    pub fn safe_remove(&mut self, registry: &Registry) {
        for index in &self.to_removed {
            if let Some(conn) = self.proxies.get_mut(index) {
                conn.close_now(registry);
            }
            self.proxies.remove(index);
        }
        self.to_removed.clear();
    }
}

impl ProxyManager {
    pub(crate) fn push(&mut self, index: usize, conn: ProxyConnection<TlsStream>) {
        self.proxies.insert(index, conn);
    }
}

impl ProxyManager {
    pub fn new() -> ProxyManager {
        Self {
            proxies: Default::default(),
            to_removed: Default::default(),
        }
    }

    pub fn resolved(&mut self, index: usize, ips: &Vec<IpAddr>, registry: &Registry) {
        self.proxies
            .get_mut(&index)
            .map(|conn| conn.resolved(ips, registry));
    }
}
