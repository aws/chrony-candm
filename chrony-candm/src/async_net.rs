// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: GPL-2.0-only

use std::collections::{HashMap, VecDeque};
use std::ffi::OsStr;
use std::fs::Permissions;
use std::future::Future;
use std::hash::{Hash, Hasher};
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::sync::Arc;

use futures::future::TryFutureExt;
use rand::Rng;
use tokio::sync::mpsc::error::SendError;
use tokio::sync::OnceCell;
use tokio::time::Instant;

use crate::reply::Reply;
use crate::request::{Request, RequestBody};
use crate::ClientOptions;

#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use tokio::net::UnixDatagram;

#[cfg(unix)]
#[derive(Debug)]
struct UnixDatagramClient(UnixDatagram);

#[cfg(unix)]
impl AsRef<UnixDatagram> for UnixDatagramClient {
    fn as_ref(&self) -> &UnixDatagram {
        &self.0
    }
}

#[cfg(unix)]
impl AsMut<UnixDatagram> for UnixDatagramClient {
    fn as_mut(&mut self) -> &mut UnixDatagram {
        &mut self.0
    }
}

#[cfg(unix)]
impl Deref for UnixDatagramClient {
    type Target = UnixDatagram;
    fn deref(&self) -> &UnixDatagram {
        &self.0
    }
}

#[cfg(unix)]
impl DerefMut for UnixDatagramClient {
    fn deref_mut(&mut self) -> &mut UnixDatagram {
        &mut self.0
    }
}

#[cfg(unix)]
impl Drop for UnixDatagramClient {
    fn drop(&mut self) {
        if let Ok(addr) = self.0.local_addr() {
            if let Some(path) = addr.as_pathname() {
                let _ = self.0.shutdown(std::net::Shutdown::Both);
                let _ = std::fs::remove_file(path);
            }
        }
    }
}

#[cfg(unix)]
impl UnixDatagramClient {
    async fn new() -> std::io::Result<UnixDatagramClient> {
        let id: [u8; 16] = rand::random();
        let mut path = b"/var/run/chrony/client-000102030405060708090a0b0c0d0e0f.sock".clone();
        hex::encode_to_slice(id, &mut path[23..55]).unwrap();
        let path_str = OsStr::from_bytes(&path);
        let sock = UnixDatagram::bind(path_str)?;
        let client = UnixDatagramClient(sock);
        std::fs::set_permissions(path_str, Permissions::from_mode(0o777))?;
        client.connect("/var/run/chrony/chronyd.sock")?;
        Ok(client)
    }
}

#[derive(Debug, Hash)]
enum ServerAddr {
    Udp(SocketAddrV6),
    #[cfg(unix)]
    Unix,
}

type ReplySender = tokio::sync::oneshot::Sender<std::io::Result<Reply>>;
type ReplyReceiver = tokio::sync::oneshot::Receiver<std::io::Result<Reply>>;
#[derive(Debug)]
struct RequestMeta {
    body: RequestBody,
    reply_sender: ReplySender,
    server: ServerAddr,
}

type RequestSender = tokio::sync::mpsc::UnboundedSender<RequestMeta>;
type RequestReceiver = tokio::sync::mpsc::UnboundedReceiver<RequestMeta>;

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
enum ServerKey {
    Udp(SocketAddr),
    #[cfg(unix)]
    Unix,
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
struct InflightKey {
    server_key: ServerKey,
    sequence: u32,
}

#[derive(Debug)]
struct InflightValue {
    request: Vec<u8>,
    attempt: u16,
    reply_sender: ReplySender,
    server: ServerAddr,
}

/// Asynchronously sends requests and receives replies
#[derive(Debug)]
pub struct Client {
    task_handle: tokio::task::JoinHandle<()>,
    sender: RequestSender,
}

/// A future which can be `await`ed to obtain the reply to a sent query
#[derive(Debug)]
pub struct ReplyFuture(ReplyReceiver);

impl Future for ReplyFuture {
    type Output = std::io::Result<Reply>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let receiver = &mut self.get_mut().0;
        let mut result = receiver.unwrap_or_else(|e| {
            Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                e,
            ))
        });
        Pin::new(&mut result).poll(cx)
    }
}

impl Client {
    /// Spawns a task to handle sending of requests and receiving of replies, and returns a `Client`
    /// that communicates with this task.
    pub fn spawn(handle: &tokio::runtime::Handle, options: crate::net::ClientOptions) -> Client {
        let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
        let task_handle = handle.spawn(client_task(options, receiver));
        Client {
            task_handle,
            sender,
        }
    }

    /// Sends a request to the given server, and returns a future which can be `await`ed to obtain the reply.
    ///
    /// Note that this is *not* an async function; it is a synchronous, non-blocking function which returns a future. Even
    /// if you don't immediately await the returned future, the request will still immediately be dispatched
    /// to the task which was spawned to service this client, which will immediately form it into a packet
    /// and send it.
    ///
    /// The type of the `server` parameter is more restrictive than that of this method's blocking counterpart
    /// [crate::net::blocking_query] because converting some implementations of `ToSocketAddrs` into a `SocketAddr` can
    /// involve blocking on a DNS lookup, which here would be unacceptable. If you're communicating with localhost,
    /// can call this method with `LOCAL_SERVER_ADDR.into()`. If you're communicating with a remote server,
    /// you'll need to handle the DNS lookup yourself.
    pub fn query(&self, request: RequestBody, server: SocketAddr) -> ReplyFuture {
        let mapped_server = match server {
            SocketAddr::V4(v4) => SocketAddrV6::new(v4.ip().to_ipv6_mapped(), v4.port(), 0, 0),
            SocketAddr::V6(v6) => v6,
        };

        let (sender, receiver) = tokio::sync::oneshot::channel();
        if let Err(SendError(request_meta)) = self.sender.send(RequestMeta {
            body: request,
            reply_sender: sender,
            server: ServerAddr::Udp(mapped_server),
        }) {
            request_meta
                .reply_sender
                .send(Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "Client task unexpectedly shut down",
                )))
                .expect("Send failed but the receiver is still in scope?!")
        }

        ReplyFuture(receiver)
    }

    /// Sends a request to the local Chrony server via its UNIX domain socket, and returns a future which can be `await`ed to obtain the reply.
    #[cfg(unix)]
    pub fn query_uds(&self, request: RequestBody) -> ReplyFuture {
        let (sender, receiver) = tokio::sync::oneshot::channel();

        if let Err(SendError(request_meta)) = self.sender.send(RequestMeta {
            body: request,
            reply_sender: sender,
            server: ServerAddr::Unix,
        }) {
            request_meta
                .reply_sender
                .send(Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "Client task unexpectedly shut down",
                )))
                .expect("Send failed but the receiver is still in scope?!")
        }

        ReplyFuture(receiver)
    }
}

#[derive(Debug)]
struct ReplyMeta<'a> {
    reply: &'a [u8],
    server_key: ServerKey,
}

#[derive(Debug)]
enum SelectResult<'a> {
    Request(RequestMeta),
    Reply(ReplyMeta<'a>),
    Timeout,
    Error(std::io::Error),
    Shutdown,
}

async fn client_task(options: ClientOptions, mut receiver: RequestReceiver) {
    let mut deadlines: VecDeque<(Instant, InflightKey)> = std::collections::VecDeque::new();
    let mut inflight: HashMap<InflightKey, InflightValue> = std::collections::HashMap::new();

    let udp_init = || tokio::net::UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0));
    let udp_cell: OnceCell<tokio::net::UdpSocket> = OnceCell::new();
    let mut udp_buf = [0u8; 1500];

    #[cfg(unix)]
    let uds_init = || UnixDatagramClient::new();
    #[cfg(unix)]
    let uds_cell: OnceCell<UnixDatagramClient> = OnceCell::new();
    #[cfg(unix)]
    let mut uds_buf = [0u8; 1500];

    let (mut sequence, key0, key1): (u32, u64, u64) = {
        let mut rng = rand::thread_rng();
        (rng.gen(), rng.gen(), rng.gen())
    };

    loop {
        let now = tokio::time::Instant::now();

        // Find expired deadlines and retransmit those messages, or give up
        // if the attempt limit has been reached
        while let Some((deadline, _)) = deadlines.front() {
            if *deadline > now {
                break;
            }
            //`deadline_key` and `inflight_key` have the same value, but
            // we keep both copies in order to minimize further cloning.
            let (_, deadline_key) = deadlines.pop_front().unwrap();
            if let Some((inflight_key, mut inflight_val)) = inflight.remove_entry(&deadline_key) {
                inflight_val.attempt += 1;
                if inflight_val.attempt > options.n_tries {
                    let _ = inflight_val.reply_sender.send(Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "request timed out and max retries reached",
                    )));
                } else {
                    crate::request::increment_attempt(inflight_val.request.as_mut());
                    let send_result = match inflight_val.server {
                        // These are retries, so we can safely unwrap() since we must have
                        // gotten a socket the first time around.
                        ServerAddr::Udp(addr) => {
                            udp_cell
                                .get()
                                .unwrap()
                                .send_to(inflight_val.request.as_ref(), addr)
                                .await
                        }
                        #[cfg(unix)]
                        ServerAddr::Unix => {
                            uds_cell
                                .get()
                                .unwrap()
                                .send(inflight_val.request.as_ref())
                                .await
                        }
                    };
                    match send_result {
                        Ok(_) => {
                            inflight.insert(inflight_key, inflight_val);
                            let new_deadline = now + options.timeout;
                            deadlines.push_back((new_deadline, deadline_key));
                        }
                        Err(e) => {
                            let _ = inflight_val.reply_sender.send(Err(e));
                        }
                    }
                }
            }
        }

        // Cull unexpired deadlines that have already been met. On every iteration of
        // the main loop, pop off the front of the queue until we reach something
        // still in-flight. This takes amortized O(1), and it ensures that the next
        // coming deadline is "real" and prevents unnecessary wakeups.
        while let Some((_, inflight_key)) = deadlines.front() {
            if inflight.contains_key(inflight_key) {
                break;
            } else {
                deadlines.pop_front();
            }
        }

        // In rare cases, like if the network comes back online in the middle of a
        // big burst of queries, there might be a lot of met deadlines still remaining
        // in the queue. Finding these takes O(N), so we don't want to do it every time.
        // Instead, we do a complete cull only when the length of `deadlines` reaches
        // twice the capacity of `inflight`. This keeps us at amortized O(1) and also
        // keeps the deadline queue from asymptotically outgrowing the inflight table.
        if deadlines.len() >= 2 * inflight.capacity() {
            deadlines.retain(|(_, inflight_key)| inflight.contains_key(inflight_key))
        }

        let timeout = async {
            match deadlines.front() {
                Some((deadline, _)) => tokio::time::sleep_until(*deadline).await,
                None => futures::future::pending().await,
            }
        };

        let udp_recv = async {
            match udp_cell.get() {
                Some(udp) => {
                    let (size, peer) = udp.recv_from(&mut udp_buf).await?;
                    std::io::Result::Ok(ReplyMeta {
                        reply: &udp_buf[0..size],
                        server_key: ServerKey::Udp(peer),
                    })
                }
                _ => futures::future::pending().await,
            }
        };

        #[cfg(unix)]
        let uds_recv = async {
            match uds_cell.get() {
                Some(uds) => {
                    let size = uds.recv(&mut uds_buf).await?;
                    std::io::Result::Ok(ReplyMeta {
                        reply: &uds_buf[0..size],
                        server_key: ServerKey::Unix,
                    })
                }
                _ => futures::future::pending().await,
            }
        };
        #[cfg(not(unix))]
        let uds_recv = futures::future::pending();

        let select_result = tokio::select! {
            result = udp_recv => match result {
                Ok(reply_meta) => {
                    SelectResult::Reply(reply_meta)
                },
                Err(e) => SelectResult::Error(e),
            },
            result = uds_recv => match result {
                Ok(reply_meta) => {
                    SelectResult::Reply(reply_meta)
                },
                Err(e) => SelectResult::Error(e),
            },
            result = receiver.recv() => {
                match result {
                    Some(request) => SelectResult::Request(request),
                    None => SelectResult::Shutdown,
                }
            },
            _ = timeout => SelectResult::Timeout
        };

        match select_result {
            SelectResult::Request(request_meta) => {
                // Sequnce numbers should be unpredictable in order to make
                // off-path blind spoofing harder. A single global sequence
                // number accumulator with a random initial state is mixed
                // with a server-specific key derived using SipHash. This
                // way we don't have to keep state for each individual server,
                // sequence numbers sent to one server can't be used to guess
                // another's, and we avoid the birthday-bound collisions that
                // we'd get from picking a random number for every request.
                let mut hasher = siphasher::sip::SipHasher::new_with_keys(key0, key1);
                request_meta.server.hash(&mut hasher);
                let obfuscated_sequence = sequence.wrapping_add(hasher.finish() as u32);
                sequence = sequence.wrapping_add(1);

                let request = Request {
                    sequence: obfuscated_sequence,
                    attempt: 0,
                    body: request_meta.body,
                };
                let mut send_buf = Vec::with_capacity(request.length());
                request.serialize(&mut send_buf);

                let inflight_key = InflightKey {
                    server_key: match request_meta.server {
                        ServerAddr::Udp(addr) => ServerKey::Udp(addr.into()),
                        #[cfg(unix)]
                        ServerAddr::Unix => ServerKey::Unix,
                    },
                    sequence: obfuscated_sequence,
                };

                let inflight_val = InflightValue {
                    request: send_buf,
                    attempt: 0,
                    reply_sender: request_meta.reply_sender,
                    server: request_meta.server,
                };

                let deadline = now + options.timeout;

                match inflight_val.server {
                    ServerAddr::Udp(addr) => match udp_cell.get_or_try_init(udp_init).await {
                        Ok(udp) => {
                            if let Err(e) = udp.send_to(inflight_val.request.as_ref(), addr).await {
                                let _ = inflight_val.reply_sender.send(Err(e));
                                continue;
                            }
                        }
                        Err(e) => {
                            let _ = inflight_val.reply_sender.send(Err(e));
                            continue;
                        }
                    },
                    #[cfg(unix)]
                    ServerAddr::Unix => match uds_cell.get_or_try_init(uds_init).await {
                        Ok(uds) => {
                            if let Err(e) = uds.send(inflight_val.request.as_ref()).await {
                                let _ = inflight_val.reply_sender.send(Err(e));
                                continue;
                            }
                        }
                        Err(e) => {
                            let _ = inflight_val.reply_sender.send(Err(e));
                            continue;
                        }
                    },
                }

                deadlines.push_back((deadline, inflight_key.clone()));
                inflight.insert(inflight_key.clone(), inflight_val);
            }
            SelectResult::Reply(reply_meta) => {
                let mut reply_buf = reply_meta.reply;
                if let Ok(reply) = Reply::deserialize(&mut reply_buf) {
                    let inflight_key = InflightKey {
                        server_key: reply_meta.server_key,
                        sequence: reply.sequence,
                    };
                    if let Some(inflight_val) = inflight.remove(&inflight_key) {
                        let _ = inflight_val.reply_sender.send(Ok(reply));
                    }
                }
            }
            SelectResult::Timeout => {}
            SelectResult::Error(e) => {
                if e.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }

                // Any other kind of error should never happen here, but if it
                // does we have to bail.
                let erc = Arc::new(e);
                receiver.close();
                // Drain any requests from the channel and answer them all with the error
                // we got.
                while let Some(request) = receiver.recv().await {
                    let _ = request
                        .reply_sender
                        .send(Err(std::io::Error::new(erc.kind(), erc.clone())));
                }
                // Also answer in-flight requests with an error.
                for v in inflight.into_values() {
                    let _ = v
                        .reply_sender
                        .send(Err(std::io::Error::new(erc.kind(), erc.clone())));
                }
                return;
            }
            SelectResult::Shutdown => {
                for v in inflight.into_values() {
                    let _ = v.reply_sender.send(Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionAborted,
                        "Client dropped before arrival of reply",
                    )));
                }
                return;
            }
        }
    }
}
