// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: GPL-2.0-only

use bytes::BytesMut;
use rand::Rng;

use crate::reply::Reply;
use crate::request::{increment_attempt, Request, RequestBody};

use std::ffi::OsStr;
use std::fs::Permissions;
use std::net::Ipv6Addr;
use std::ops::{Deref, DerefMut};
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::os::unix::net::UnixDatagram;

pub const DEFAULT_PORT: u16 = 323;

/// Options for configuring a Chrony client
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ClientOptions {
    /// How long to wait for a reply before assuming the request was dropped (default: 1s)
    pub timeout: Duration,
    /// Number of times to try a request before giving up (default: 3)
    pub n_tries: u16,
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            n_tries: 3,
            timeout: Duration::from_secs(1),
        }
    }
}

///Common interface to `UdpSocket` and `UnixDatagram` to avoid copypasta between our two `blocking_query` functions
trait DgramSocket {
    fn send(&self, buf: &[u8]) -> std::io::Result<usize>;
    fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize>;
}

impl DgramSocket for std::net::UdpSocket {
    fn send(&self, buf: &[u8]) -> std::io::Result<usize> {
        std::net::UdpSocket::send(self, buf)
    }

    fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        std::net::UdpSocket::recv(self, buf)
    }
}

#[cfg(unix)]
impl DgramSocket for UnixDatagram {
    fn send(&self, buf: &[u8]) -> std::io::Result<usize> {
        UnixDatagram::send(self, buf)
    }

    fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        UnixDatagram::recv(self, buf)
    }
}

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
    fn new() -> std::io::Result<UnixDatagramClient> {
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

fn blocking_query_loop<Sock: DgramSocket>(
    sock: &Sock,
    request_body: RequestBody,
    options: ClientOptions,
) -> std::io::Result<Reply> {
    let request = Request {
        sequence: rand::thread_rng().gen(),
        attempt: 0,
        body: request_body,
    };

    let mut send_buf = BytesMut::with_capacity(request.length());
    request.serialize(&mut send_buf);
    let mut recv_buf = [0; 1500];
    let mut attempt = 0;

    loop {
        sock.send(send_buf.as_ref())?;
        match sock.recv(&mut recv_buf) {
            Ok(len) => {
                let mut msg = &recv_buf[0..len];
                match Reply::deserialize(&mut msg) {
                    Ok(reply) => {
                        if reply.sequence == request.sequence {
                            return Ok(reply);
                        } else {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "Bad sequence number",
                            ));
                        }
                    }
                    Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
                }
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::TimedOut
                    || e.kind() == std::io::ErrorKind::WouldBlock
                {
                    attempt += 1;
                    if attempt == options.n_tries {
                        return Err(e);
                    }
                    increment_attempt(send_buf.as_mut());
                } else {
                    return Err(e);
                }
            }
        }
    }
}

/// Sends a request to a server via UDP and waits for a reply
pub fn blocking_query<Server: std::net::ToSocketAddrs>(
    request_body: RequestBody,
    options: ClientOptions,
    server: &Server,
) -> std::io::Result<Reply> {
    let sock = std::net::UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0))?;
    sock.connect(server)?;
    sock.set_read_timeout(Some(options.timeout))?;

    blocking_query_loop(&sock, request_body, options)
}

/// Sends a request to a server via a domain socket and waits for a reply
#[cfg(unix)]
pub fn blocking_query_uds(
    request_body: RequestBody,
    options: ClientOptions,
) -> std::io::Result<Reply> {
    let sock = UnixDatagramClient::new()?;
    sock.set_read_timeout(Some(options.timeout))?;
    blocking_query_loop(sock.as_ref(), request_body, options)
}
