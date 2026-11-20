//! A deterministic loopback DNS peer: it answers from a table and records every question.

extern crate alloc;

use alloc::sync::Arc;
use core::net::SocketAddr;
use std::{io, sync::Mutex};

use hickory_resolver::proto::{
    op::{Message, ResponseCode},
    rr::{Name, RData, Record, RecordType},
};
use tokio::{net::UdpSocket, task::JoinHandle};

use crate::{TestError, loopback};

/// What the peer answers to one question.
pub(crate) enum Reply {
    /// These records, NOERROR.
    Records(Vec<RData>),
    /// NOERROR with an empty answer (NODATA).
    NoData,
    /// An answer-less response with this code (for example NXDOMAIN or SERVFAIL).
    Code(ResponseCode),
}

/// One row of the table: lower-case fully qualified name, type, answer.
type Rule = (String, RecordType, Reply);

/// A running peer. Dropping it stops it.
pub(crate) struct Dns {
    /// The loopback address the peer listens on.
    addr: SocketAddr,
    /// Every question received, as `"<type> <name>"`, in arrival order.
    log: Arc<Mutex<Vec<String>>>,
    /// The serving task.
    task: JoinHandle<()>,
}

impl Dns {
    /// Start a peer that answers `rules`; a question no rule matches gets NXDOMAIN.
    pub(crate) async fn start<I>(rules: I) -> Result<Self, TestError>
    where
        I: IntoIterator<Item = (&'static str, RecordType, Reply)>,
    {
        let socket = loopback::bind(false).await?;
        let addr = socket.local_addr()?;
        let table: Vec<Rule> = rules
            .into_iter()
            .map(|(name, kind, reply)| (name.to_ascii_lowercase(), kind, reply))
            .collect();
        let log = Arc::new(Mutex::new(Vec::new()));
        let task = tokio::spawn(serve(socket, table, Arc::clone(&log)));
        Ok(Self { addr, log, task })
    }

    /// The loopback address the peer listens on.
    pub(crate) const fn address(&self) -> SocketAddr {
        self.addr
    }

    /// Every question received so far, as `"<type> <name>"`.
    pub(crate) fn questions(&self) -> Result<Vec<String>, TestError> {
        Ok(self
            .log
            .lock()
            .map_err(|_poisoned| io::Error::other("question log poisoned"))?
            .clone())
    }
}

impl Drop for Dns {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Answer questions until the task is aborted.
async fn serve(socket: UdpSocket, table: Vec<Rule>, log: Arc<Mutex<Vec<String>>>) {
    loop {
        let mut buffer = [0_u8; 4096];
        let Ok((length, peer)) = socket.recv_from(&mut buffer).await else {
            return;
        };
        let Some(datagram) = buffer.get(..length) else {
            continue;
        };
        let Ok(request) = Message::from_vec(datagram) else {
            continue;
        };
        let Some(query) = request.queries.first() else {
            continue;
        };
        let name = query.name().to_ascii().to_ascii_lowercase();
        if let Ok(mut questions) = log.lock() {
            questions.push(format!("{:?} {name}", query.query_type()));
        }
        let mut response = Message::response(request.metadata.id, request.metadata.op_code);
        response.metadata.authoritative = true;
        response.metadata.recursion_available = true;
        response.queries.clone_from(&request.queries);
        let found = table
            .iter()
            .find(|(rule_name, kind, _)| *rule_name == name && *kind == query.query_type());
        match found.map(|(_, _, reply)| reply) {
            Some(Reply::Records(records)) => {
                for data in records {
                    response.answers.push(Record::from_rdata(
                        query.name().clone(),
                        60,
                        data.clone(),
                    ));
                }
            }
            Some(Reply::NoData) => {}
            Some(Reply::Code(code)) => response.metadata.response_code = *code,
            None => response.metadata.response_code = ResponseCode::NXDomain,
        }
        let Ok(bytes) = response.to_vec() else {
            continue;
        };
        if socket.send_to(&bytes, peer).await.is_err() {
            return;
        }
    }
}

/// A fully qualified [`Name`].
pub(crate) fn name(text: &str) -> Result<Name, TestError> {
    Ok(Name::from_ascii(text)?)
}
