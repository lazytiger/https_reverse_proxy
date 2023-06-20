use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use mio::event::Source;
use mio::net::UdpSocket;
use mio::{Interest, Registry, Token};
use trust_dns_proto::op::{Message, Query};
use trust_dns_proto::rr::{Name, RecordType};
use trust_dns_proto::serialize::binary::BinDecodable;

use crate::proxy_manager::ProxyManager;
use crate::types::Result;

pub struct DnsResolver {
    socket: UdpSocket,
    queries: HashMap<String, HashSet<usize>>,
    answer: HashMap<String, Vec<IpAddr>>,
    dns_server: SocketAddr,
    id: u16,
}

impl DnsResolver {
    pub fn new(dns_server: String, token: Token, registry: &Registry) -> Result<Self> {
        let addr = dns_server + ":53";
        let dns_server = addr.parse()?;
        let mut socket = UdpSocket::bind(SocketAddr::from_str("0.0.0.0:0")?)?;
        socket.register(registry, token, Interest::READABLE)?;
        Ok(Self {
            socket,
            dns_server,
            queries: Default::default(),
            answer: Default::default(),
            id: 0,
        })
    }
    pub fn query(&mut self, name: &str, index: usize) -> Result<()> {
        let mut name = name.to_string();
        if !name.ends_with('.') {
            name.push('.');
        }
        let mut query = Query::new();
        query.set_query_type(RecordType::A);
        query.set_name(Name::from_str(name.as_str())?);
        let mut message = Message::new();
        message.set_recursion_desired(true);
        message.set_id(self.id);
        message.queries_mut().push(query);
        self.id += 1;
        self.socket
            .send_to(message.to_vec()?.as_slice(), self.dns_server)?;
        self.queries.entry(name).or_default().insert(index);
        Ok(())
    }

    pub fn resolve(&mut self, manager: &mut ProxyManager, registry: &Registry) -> Result<()> {
        let mut buffer = vec![0u8; 1500];
        while let Ok(n) = self.socket.recv(buffer.as_mut_slice()) {
            if let Ok(message) = Message::from_bytes(&buffer.as_slice()[..n]) {
                let name = message.query().unwrap().name().to_string();
                let data: Vec<_> = message
                    .answers()
                    .iter()
                    .filter_map(|r| r.data().map(|data| data.to_ip_addr()).unwrap_or_default())
                    .collect();
                self.answer.insert(name, data);
            }
        }
        self.dispatch(manager, registry)
    }

    pub fn dispatch(&mut self, manager: &mut ProxyManager, registry: &Registry) -> Result<()> {
        let answer = std::mem::take(&mut self.answer);
        for (name, data) in &answer {
            if let Some(set) = self.queries.get(name) {
                for index in set {
                    manager.resolved(*index, data, registry);
                }
            }
        }
        for (name, _) in &answer {
            self.queries.remove(name);
        }
        Ok(())
    }
}
