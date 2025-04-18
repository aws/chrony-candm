// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Portions derived from Chrony copyright Richard P. Curnow 1997-2003
// and Miroslav Lichvar 2009, 2012-2020
// SPDX-License-Identifier: GPL-2.0-only

//! Data structures occurring both in requests and in replies

use bitflags::bitflags;
use bytes::{Buf, BufMut};
use std::convert::From;
use std::error::Error;
use std::fmt::{Debug, Display};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chrony_candm_derive::ChronySerialize;

#[derive(Debug, thiserror::Error)]
pub enum QueryError {
    #[error("Unable to send request")]
    Send(#[source] std::io::Error),
    #[error("Unable to receive reply")]
    Recv(#[source] std::io::Error),
    #[error("Failed deserialization")]
    Deserialization(#[from] DeserializationError),
    #[error("Sequence number mismatch. Expected {expected}, got {received}")]
    SequenceMismatch { expected: u32, received: u32 },
    #[error("Timeout")]
    Timeout,
}

impl QueryError {
    // Convert to IO error for backwards compatibility
    pub(crate) fn into_io(self) -> std::io::Error {
        match self {
            QueryError::Send(e) => e,
            QueryError::Recv(e) => e,
            QueryError::Deserialization(e) => std::io::Error::new(std::io::ErrorKind::InvalidData, e),
            QueryError::SequenceMismatch { .. } => std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                String::from("Sequence number mismatch"),
            ),
            QueryError::Timeout => std::io::Error::new(std::io::ErrorKind::TimedOut, "Timed out"),
        }
    }
}

///Error returned when attempting to deserialize a malformed message
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct DeserializationError(Option<&'static str>);

impl DeserializationError {
    pub(crate) fn new(detail: &'static str) -> DeserializationError {
        DeserializationError(Some(detail))
    }

    #[allow(dead_code)]
    pub(crate) fn generic() -> DeserializationError {
        DeserializationError(None)
    }
}

impl Display for DeserializationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            None => write!(f, "Deserialization error"),
            Some(detail) => write!(f, "Deserialization error: {}", detail),
        }
    }
}
impl Error for DeserializationError {}

pub(crate) trait ChronySerialize: Sized {
    fn length() -> usize;
    fn serialize<B: BufMut>(&self, buf: &mut B);
    fn deserialize_unchecked<B: Buf>(buf: &mut B) -> Result<Self, DeserializationError>;

    fn deserialize<B: Buf>(buf: &mut B) -> Result<Self, DeserializationError> {
        if buf.remaining() < Self::length() {
            Err(DeserializationError::new("message too short"))
        } else {
            Self::deserialize_unchecked(buf)
        }
    }
}

impl<T: ChronySerialize + Copy, const N: usize> ChronySerialize for [T; N] {
    fn length() -> usize {
        T::length() * N
    }

    fn serialize<B: BufMut>(&self, buf: &mut B) {
        for i in 0..N {
            self[i].serialize(buf)
        }
    }

    fn deserialize_unchecked<B: Buf>(buf: &mut B) -> Result<Self, DeserializationError> {
        let mut arr = arrayvec::ArrayVec::<T, N>::new_const();
        unsafe {
            for _ in 0..N {
                //Safety: We push at most N elements
                arr.push_unchecked(T::deserialize_unchecked(buf)?);
            }
            //Safety: we've pushed exactly N elements
            Ok(arr.into_inner_unchecked())
        }
    }
}

macro_rules! serialize_primitive {
    ($ty:ty, $get:ident, $put:ident) => {
        impl ChronySerialize for $ty {
            fn length() -> usize {
                std::mem::size_of::<$ty>()
            }

            fn serialize<B: BufMut>(&self, buf: &mut B) {
                buf.$put(*self)
            }

            fn deserialize_unchecked<B: Buf>(buf: &mut B) -> Result<Self, DeserializationError> {
                Ok(buf.$get())
            }
        }
    };
}

serialize_primitive!(u8, get_u8, put_u8);
serialize_primitive!(i8, get_i8, put_i8);
serialize_primitive!(u16, get_u16, put_u16);
serialize_primitive!(i16, get_i16, put_i16);
serialize_primitive!(u32, get_u32, put_u32);
serialize_primitive!(i32, get_i32, put_i32);
serialize_primitive!(u64, get_u64, put_u64);
serialize_primitive!(i64, get_i64, put_i64);

impl ChronySerialize for SystemTime {
    fn length() -> usize {
        12
    }

    fn serialize<B: BufMut>(&self, buf: &mut B) {
        let (secs, nsecs) = match self.duration_since(UNIX_EPOCH) {
            Ok(d) => (d.as_secs() as i64, d.subsec_nanos()),
            Err(e) => {
                let d = e.duration();
                let secs = d.as_secs() as i64;
                let nsecs = d.subsec_nanos();
                if nsecs == 0 {
                    (-secs, 0)
                } else {
                    (-secs - 1, 1_000_000_000 - nsecs)
                }
            }
        };

        let secs_high = (secs >> 32) as i32;
        let secs_low = (secs & 0xffffffff) as u32;

        buf.put_i32(secs_high);
        buf.put_u32(secs_low);
        buf.put_u32(nsecs);
    }

    fn deserialize_unchecked<B: Buf>(buf: &mut B) -> Result<Self, DeserializationError> {
        let secs_high_orig = buf.get_i32();
        let secs_low = buf.get_u32();
        let nsecs = buf.get_u32();

        let secs_high = if secs_high_orig == i32::MAX {
            0
        } else {
            secs_high_orig
        };

        if secs_high >= 0 {
            let d = Duration::from_secs((secs_high as u64) << 32)
                + Duration::from_secs(secs_low as u64)
                + Duration::from_nanos(nsecs as u64);
            Ok(UNIX_EPOCH + d)
        } else {
            let d = Duration::from_secs(((-secs_high) as u64) << 32)
                - Duration::from_secs(secs_low as u64)
                - Duration::from_nanos(nsecs as u64);
            Ok(UNIX_EPOCH - d)
        }
    }
}
pub(crate) trait ChronyMessage: Sized {
    fn body_length(&self) -> usize;
    fn cmd(&self) -> u16;
    fn serialize_body<B: BufMut>(&self, buf: &mut B);
    fn deserialize_body<B: Buf>(cmd: u16, body: &mut B) -> Result<Self, DeserializationError>;
}

/// Floating point number as used in Chrony's wire protocol
///
/// A `ChronyFloat` can be converted infallibly to and from an `f64`,
/// but the conversion into `ChronyFloat` is lossy and sometimes
/// nonsensical, e.g., NaNs are represented as 0. These conversion
/// rules are identical to the ones that Chrony uses internally.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Default)]
pub struct ChronyFloat(u32);

impl Debug for ChronyFloat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ChronyFloat")
            .field(&f64::from(*self))
            .finish()
    }
}

impl Display for ChronyFloat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&f64::from(*self), f)
    }
}

impl PartialOrd for ChronyFloat {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        f64::from(*self).partial_cmp(&f64::from(*other))
    }
}

impl Ord for ChronyFloat {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.partial_cmp(other)
            .expect("Conversion from ChronyFloat yielded incomparable f64")
    }
}

const FLOAT_EXP_BITS: u32 = 7;
const FLOAT_EXP_MIN: i32 = -((1 << (FLOAT_EXP_BITS - 1)) as i32);
const FLOAT_EXP_MAX: i32 = -FLOAT_EXP_MIN - 1;
const FLOAT_COEF_BITS: u32 = 32 - FLOAT_EXP_BITS;
const FLOAT_COEF_MIN: i32 = -((1 << (FLOAT_COEF_BITS - 1)) as i32);
const FLOAT_COEF_MAX: i32 = -FLOAT_COEF_MIN - 1;

impl From<ChronyFloat> for f64 {
    fn from(f: ChronyFloat) -> Self {
        let ChronyFloat(x) = f;

        let mut exp = (x >> FLOAT_COEF_BITS) as i32;
        if exp >= 1 << (FLOAT_EXP_BITS - 1) {
            exp -= 1 << FLOAT_EXP_BITS;
        }
        exp -= FLOAT_COEF_BITS as i32;

        let mut coef = (x % (1 << FLOAT_COEF_BITS)) as i32;

        if coef >= 1 << (FLOAT_COEF_BITS - 1) {
            coef -= 1 << FLOAT_COEF_BITS
        }

        (coef as f64) * 2.0f64.powi(exp)
    }
}

impl From<f64> for ChronyFloat {
    fn from(f: f64) -> Self {
        let (neg, x) = if f < 0. {
            (1, -f)
        } else if f >= 0. {
            (0, f)
        } else {
            (0, 0.) //Treat NaN as zero
        };

        let mut exp: i32;
        let mut coef: i32;

        if x < 1e-100 {
            coef = 0;
            exp = 0;
        } else if x > 1e100 {
            coef = FLOAT_COEF_MAX + neg;
            exp = FLOAT_EXP_MAX;
        } else {
            exp = x.log2() as i32 + 1;
            coef = (x * 2.0f64.powi(-exp + FLOAT_COEF_BITS as i32) + 0.5) as i32;
            debug_assert!(coef > 0);

            while coef > FLOAT_COEF_MAX + neg {
                coef >>= 1;
                exp += 1;
            }

            if exp > FLOAT_EXP_MAX {
                exp = FLOAT_EXP_MAX;
                coef = FLOAT_COEF_MAX + neg;
            } else if exp < FLOAT_EXP_MIN {
                if exp + FLOAT_COEF_BITS as i32 >= FLOAT_EXP_MIN {
                    coef >>= FLOAT_EXP_MIN - exp;
                    exp = FLOAT_EXP_MIN;
                } else {
                    exp = 0;
                    coef = 0;
                }
            }
        };

        if neg != 0 {
            coef = ((-coef as u32) << FLOAT_EXP_BITS >> FLOAT_EXP_BITS) as i32;
        }

        ChronyFloat((exp as u32) << FLOAT_COEF_BITS | coef as u32)
    }
}

impl ChronySerialize for ChronyFloat {
    fn length() -> usize {
        4
    }

    fn serialize<B: BufMut>(&self, buf: &mut B) {
        self.0.serialize(buf)
    }

    fn deserialize_unchecked<B: Buf>(buf: &mut B) -> Result<Self, DeserializationError> {
        Ok(ChronyFloat(u32::deserialize_unchecked(buf)?))
    }
}

/// A network address as used in Chrony's wire protocol
#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash)]
pub enum ChronyAddr {
    /// An unknown or unspecified address
    Unspec,
    /// An IPv4 address
    V4(Ipv4Addr),
    /// An IPv6 address
    V6(Ipv6Addr),
    /// A placeholder for an address that has not yet been resolved
    Id(u32),
}

impl Default for ChronyAddr {
    fn default() -> Self {
        Self::Unspec
    }
}

impl From<Ipv4Addr> for ChronyAddr {
    fn from(addr: Ipv4Addr) -> Self {
        Self::V4(addr)
    }
}

impl From<Ipv6Addr> for ChronyAddr {
    fn from(addr: Ipv6Addr) -> Self {
        Self::V6(addr)
    }
}

impl From<IpAddr> for ChronyAddr {
    fn from(addr: IpAddr) -> Self {
        match addr {
            IpAddr::V4(addr4) => Self::V4(addr4),
            IpAddr::V6(addr6) => Self::V6(addr6),
        }
    }
}

impl Display for ChronyAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChronyAddr::Unspec => write!(f, "[UNSPEC]"),
            ChronyAddr::V4(v4) => Display::fmt(v4, f),
            ChronyAddr::V6(v6) => Display::fmt(v6, f),
            ChronyAddr::Id(id) => write!(f, "ID#{}", id),
        }
    }
}

const IPADDR_UNSPEC: u16 = 0;
const IPADDR_INET4: u16 = 1;
const IPADDR_INET6: u16 = 2;
const IPADDR_ID: u16 = 3;

impl ChronySerialize for ChronyAddr {
    fn length() -> usize {
        20
    }

    fn serialize<B: BufMut>(&self, buf: &mut B) {
        match self {
            ChronyAddr::Unspec => {
                buf.put(&[0u8; 16] as &[u8]);
                buf.put_u16(IPADDR_UNSPEC);
                buf.put_u16(0);
            }
            ChronyAddr::V4(addr) => {
                buf.put_u32((*addr).into());
                buf.put(&[0u8; 12] as &[u8]);
                buf.put_u16(IPADDR_INET4);
                buf.put_u16(0);
            }
            ChronyAddr::V6(addr) => {
                buf.put_u128((*addr).into());
                buf.put_u16(IPADDR_INET6);
                buf.put_u16(0);
            }
            ChronyAddr::Id(id) => {
                buf.put_u32(*id);
                buf.put(&[0u8; 12] as &[u8]);
                buf.put_u16(IPADDR_ID);
                buf.put_u16(0);
            }
        }
    }

    fn deserialize_unchecked<B: Buf>(buf: &mut B) -> Result<Self, DeserializationError> {
        let mut addr = buf.copy_to_bytes(16);
        let family = buf.get_u16();
        buf.get_u16();

        match family {
            IPADDR_INET4 => Ok(Self::V4(Ipv4Addr::from(addr.get_u32()))),
            IPADDR_INET6 => Ok(Self::V6(Ipv6Addr::from(addr.get_u128()))),
            IPADDR_ID => Ok(Self::Id(addr.get_u32())),
            _ => Ok(Self::Unspec),
        }
    }
}

bitflags! {
    /// Flags associated with a time source
    #[derive(ChronySerialize)]
    pub struct SourceFlags : u16 {
        const ONLINE = 0x1;
        const AUTOOFFLINE = 0x2;
        const IBURST = 0x4;
        const PREFER = 0x8;
        const NOSELECT = 0x10;
        const TRUST = 0x20;
        const REQUIRE = 0x40;
        const INTERLEAVED = 0x80;
        const BURST = 0x100;
        const NTS = 0x200;
        const COPY = 0x400;
    }
}

pub(crate) const REQUEST_HEADER_LENGTH: usize = 20;
pub(crate) const REPLY_HEADER_LENGTH: usize = 28;
