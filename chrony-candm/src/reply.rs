// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Portions derived from Chrony copyright Richard P. Curnow 1997-2003
// and Miroslav Lichvar 2009, 2012-2020
// SPDX-License-Identifier: GPL-2.0-only

//! Data structures representing replies

use bitflags::bitflags;
use bytes::{Buf, BufMut};
use chrony_candm_derive::{ChronyMessage, ChronySerialize};
use num_enum::{IntoPrimitive, TryFromPrimitive};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::common::*;

#[repr(u16)]
#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    Ord,
    PartialOrd,
    Hash,
    IntoPrimitive,
    TryFromPrimitive,
    ChronySerialize,
)]
pub enum Status {
    Success,
    Failed,
    Unauth,
    Invalid,
    NoSuchSource,
    InvalidTs,
    NotEnabled,
    BadSubnet,
    AccessAllowed,
    AccessDenied,
    NoHostAccess,
    SourceAlreadyKnown,
    TooManySources,
    NoRtc,
    BadRtcFile,
    Inactive,
    BadSample,
    InvalidAf,
    BadPktVersion,
    BadPktLength,
    InvalidName,
}
#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, ChronySerialize)]
pub struct NSources {
    pub n_sources: u32,
}

#[repr(u16)]
#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    Ord,
    PartialOrd,
    Hash,
    IntoPrimitive,
    TryFromPrimitive,
    ChronySerialize,
)]
pub enum SourceMode {
    Client,
    Peer,
    Ref,
}

#[repr(u16)]
#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    Ord,
    PartialOrd,
    Hash,
    IntoPrimitive,
    TryFromPrimitive,
    ChronySerialize,
)]
pub enum SourceState {
    Selected,
    NonSelectable,
    Falseticker,
    Jittery,
    Unselected,
    Selectable,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, ChronySerialize)]
pub struct SourceData {
    pub ip_addr: ChronyAddr,
    pub poll: i16,
    pub stratum: u16,
    pub state: SourceState,
    pub mode: SourceMode,
    pub flags: SourceFlags,
    pub reachability: u16,
    pub since_sample: u32,
    pub orig_latest_meas: ChronyFloat,
    pub latest_meas: ChronyFloat,
    pub latest_meas_err: ChronyFloat,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, ChronySerialize)]
pub struct Tracking {
    pub ref_id: u32,
    pub ip_addr: ChronyAddr,
    pub stratum: u16,
    pub leap_status: u16,
    pub ref_time: SystemTime,
    pub current_correction: ChronyFloat,
    pub last_offset: ChronyFloat,
    pub rms_offset: ChronyFloat,
    pub freq_ppm: ChronyFloat,
    pub resid_freq_ppm: ChronyFloat,
    pub skew_ppm: ChronyFloat,
    pub root_delay: ChronyFloat,
    pub root_dispersion: ChronyFloat,
    pub last_update_interval: ChronyFloat,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, ChronySerialize)]
pub struct SourceStats {
    pub ref_id: u32,
    pub ip_addr: ChronyAddr,
    pub n_samples: u32,
    pub n_runs: u32,
    pub span_seconds: u32,
    pub sd: ChronyFloat,
    pub resid_freq_ppm: ChronyFloat,
    pub skew_ppm: ChronyFloat,
    pub est_offset: ChronyFloat,
    pub est_offset_err: ChronyFloat,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, ChronySerialize)]
pub struct Rtc {
    pub ref_time: SystemTime,
    pub n_samples: u16,
    pub n_runs: u16,
    pub span_seconds: u32,
    pub rtc_seconds_fast: ChronyFloat,
    pub rtc_gain_rate_ppm: ChronyFloat,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, ChronySerialize)]
pub struct ManualTimestamp {
    pub offset: ChronyFloat,
    pub dfreq_ppm: ChronyFloat,
    pub new_afreq_ppm: ChronyFloat,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, ChronySerialize, Default)]
pub struct ClientAccessesClient {
    pub ip: ChronyAddr,
    pub ntp_hits: u32,
    pub nke_hits: u32,
    pub cmd_hits: u32,
    pub ntp_drops: u32,
    pub nke_drops: u32,
    pub cmd_drops: u32,
    pub ntp_interval: u8,
    pub nke_interval: u8,
    pub cmd_interval: u8,
    pub ntp_timeout_interval: u8,
    pub last_ntp_hit_ago: u32,
    pub last_nke_hit_ago: u32,
    pub last_cmd_hit_ago: u32,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, ChronySerialize)]
pub struct ClientAccessesByIndex {
    pub n_indices: u32,
    pub next_index: u32,
    pub n_clients: u32,
    pub clients: [ClientAccessesClient; 8],
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, ChronySerialize)]
pub struct ServerStats {
    pub ntp_hits: u32,
    pub nke_hits: u32,
    pub cmd_hits: u32,
    pub ntp_drops: u32,
    pub nke_drops: u32,
    pub cmd_drops: u32,
    pub log_drops: u32,
    pub ntp_auth_hits: u32,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, ChronySerialize)]
pub struct ManualListSample {
    pub when: SystemTime,
    pub slewed_offset: ChronyFloat,
    pub orig_offset: ChronyFloat,
    pub residual: ChronyFloat,
}

impl Default for ManualListSample {
    fn default() -> Self {
        Self {
            when: UNIX_EPOCH,
            slewed_offset: Default::default(),
            orig_offset: Default::default(),
            residual: Default::default(),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, ChronySerialize)]
pub struct ManualList {
    pub n_samples: u32,
    pub samples: [ManualListSample; 16],
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, ChronySerialize)]
pub struct Activity {
    pub online: u32,
    pub offline: u32,
    pub burst_online: u32,
    pub burst_offline: u32,
    pub unresolved: u32,
}

bitflags! {
    #[derive(ChronySerialize)]
    pub struct SmoothingFlags : u32 {
        const ACTIVE = 0x1;
        const LEAPONLY = 0x2;
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, ChronySerialize)]
pub struct Smoothing {
    pub flags: SmoothingFlags,
    pub offset: ChronyFloat,
    pub freq_ppm: ChronyFloat,
    pub wander_ppm: ChronyFloat,
    pub last_update_ago: ChronyFloat,
    pub remaining_time: ChronyFloat,
}

bitflags! {
    #[derive(ChronySerialize)]
    pub struct NtpFlags : u16 {
        const TESTS = 0x3ff;
        const INTERLEAVED = 0x4000;
        const AUTHENTICATED = 0x8000;
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, ChronySerialize)]
pub struct NtpData {
    pub remote_addr: ChronyAddr,
    pub local_addr: ChronyAddr,
    pub remote_port: u16,
    pub leap: u8,
    pub version: u8,
    pub mode: u8,
    pub stratum: u8,
    pub poll: i8,
    pub precision: i8,
    pub root_delay: ChronyFloat,
    pub root_dispersion: ChronyFloat,
    pub ref_id: u32,
    pub ref_time: SystemTime,
    pub offset: ChronyFloat,
    pub peer_delay: ChronyFloat,
    pub peer_dispersion: ChronyFloat,
    pub response_time: ChronyFloat,
    pub jitter_asymmetry: ChronyFloat,
    pub flags: NtpFlags,
    pub tx_tss_char: u8,
    pub rx_tss_char: u8,
    pub total_tx_count: u32,
    pub total_rx_count: u32,
    #[pad = 16]
    pub total_valid_count: u32,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, ChronySerialize)]
pub struct NtpSourceName {
    pub name: [u8; 256],
}

#[repr(u16)]
#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    Ord,
    PartialOrd,
    Hash,
    IntoPrimitive,
    TryFromPrimitive,
    ChronySerialize,
)]
pub enum AuthDataMode {
    None,
    Symmetric,
    Nts,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, ChronySerialize)]
pub struct AuthData {
    pub mode: AuthDataMode,
    pub key_type: u16,
    pub key_id: u32,
    pub key_length: u16,
    pub ke_attempts: u16,
    pub last_ke_ago: u32,
    pub cookies: u16,
    pub cookies_length: u16,
    #[pad = 2]
    pub nak: u16,
}

bitflags! {
    #[derive(ChronySerialize)]
    pub struct SelectDataOptions : u16 {
        const NOSELECT = 0x1;
        const PREFER = 0x2;
        const TRUST = 0x4;
        const REQUIRE = 0x8;
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, ChronySerialize)]
pub struct SelectData {
    pub ref_id: u32,
    pub ip_addr: ChronyAddr,
    pub state_char: u8,
    pub authentication: u8,
    pub leap: u8,
    pub pad: u8,
    pub conf_options: SelectDataOptions,
    pub eff_options: SelectDataOptions,
    pub last_sample_ago: u32,
    pub score: ChronyFloat,
    pub lo_limit: ChronyFloat,
    pub hi_limit: ChronyFloat,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, ChronyMessage)]
pub enum ReplyBody {
    #[cmd = 1]
    Null,
    NSources(NSources),
    SourceData(SourceData),
    ManualTimestamp,
    Tracking(Tracking),
    SourceStats(SourceStats),
    Rtc(Rtc),
    #[cmd = 12]
    Activity(Activity),
    Smoothing(Smoothing),
    #[cmd = 16]
    NtpData(NtpData),
    ManualTimestamp2(ManualTimestamp),
    ManualList2(ManualList),
    NtpSourceName(NtpSourceName),
    AuthData(AuthData),
    ClientAccessesByIndex3(ClientAccessesByIndex),
    ServerStats2(ServerStats),
    SelectData(SelectData),
}

/// A reply from Chrony
#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash)]
pub struct Reply {
    /// Status code associated with the reply
    pub status: Status,
    /// Command number associated with the request this is replying to
    pub cmd: u16,
    /// Sequence number associated with the request this is replying to
    pub sequence: u32,
    /// Body of the reply
    pub body: ReplyBody,
}

impl Reply {
    /// Returns the length in bytes of this reply when serialized.
    pub fn length(&self) -> usize {
        REPLY_HEADER_LENGTH + self.body.body_length()
    }

    /// Serializes this reply into `buf`. May panic if `buf` does not
    /// have a capacity of at least `self.length()` and its implementation
    /// does not support automatic resizing.
    pub fn serialize<B: BufMut>(&self, buf: &mut B) {
        let reply = self.body.cmd();

        buf.put_u8(6); //Version
        buf.put_u8(2); //Packet type = reply
        buf.put_u8(0); //Reserved
        buf.put_u8(0); //Reserved
        buf.put_u16(self.cmd); //Requested command, set to 0 since it's just ignored
        buf.put_u16(reply);
        self.status.serialize(buf);
        buf.put_u16(0); //Padding
        buf.put_u16(0); //Padding
        buf.put_u16(0); //Padding
        buf.put_u32(self.sequence);
        buf.put_u32(0); //Padding
        buf.put_u32(0); //Padding
        self.body.serialize_body(buf);
    }

    /// Deserializes a reply from `buf`.
    pub fn deserialize<B: Buf>(buf: &mut B) -> Result<Self, DeserializationError> {
        if buf.remaining() < REPLY_HEADER_LENGTH {
            return Err(DeserializationError::new("message too short"));
        }
        if buf.get_u8() != 6 {
            //Version
            return Err(DeserializationError::new("unsupported version"));
        }

        if buf.get_u8() != 2 {
            //Packet type
            return Err(DeserializationError::new("wrong packet type"));
        }

        buf.get_u8(); //Reserved
        buf.get_u8(); //Reserved
        let cmd = buf.get_u16();
        let reply = buf.get_u16();
        let status = Status::deserialize_unchecked(buf)?;
        buf.get_u16(); //Padding
        buf.get_u16(); //Padding
        buf.get_u16(); //Padding
        let sequence = buf.get_u32();
        buf.get_u32(); //Padding
        buf.get_u32(); //Padding
        let body = ReplyBody::deserialize_body(reply, buf)?;
        Ok(Self {
            status,
            cmd,
            sequence,
            body,
        })
    }
}
