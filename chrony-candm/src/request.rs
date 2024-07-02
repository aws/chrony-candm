// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Portions derived from Chrony copyright Richard P. Curnow 1997-2003
// and Miroslav Lichvar 2009, 2012-2020
// SPDX-License-Identifier: GPL-2.0-only

//! Data structures representing requests

use bytes::{Buf, BufMut};
use chrony_candm_derive::{ChronyMessage, ChronySerialize};
use num_enum::{IntoPrimitive, TryFromPrimitive};
use std::{convert::TryInto, time::SystemTime};

use crate::common::*;
use crate::reply;

#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, ChronySerialize)]
pub struct Online {
    pub mask: ChronyAddr,
    pub address: ChronyAddr,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, ChronySerialize)]
pub struct Offline {
    pub mask: ChronyAddr,
    pub address: ChronyAddr,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, ChronySerialize)]
pub struct Burst {
    pub mask: ChronyAddr,
    pub address: ChronyAddr,
    pub n_good_samples: i32,
    pub n_total_samples: i32,
}
#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, ChronySerialize)]
pub struct ModifyMinPoll {
    pub address: ChronyAddr,
    pub new_minpoll: i32,
}
#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, ChronySerialize)]
pub struct ModifyMaxPoll {
    pub address: ChronyAddr,
    pub new_maxpoll: i32,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, ChronySerialize)]
pub struct ModifyMaxDelay {
    pub address: ChronyAddr,
    pub new_max_delay: ChronyFloat,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, ChronySerialize)]
pub struct ModifyMaxDelayRatio {
    pub address: ChronyAddr,
    pub new_max_delay_ratio: ChronyFloat,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, ChronySerialize)]
pub struct ModifyMaxDelayDevRatio {
    pub address: ChronyAddr,
    pub new_max_delay_dev_ratio: ChronyFloat,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, ChronySerialize)]
pub struct ModifyMinStratum {
    pub address: ChronyAddr,
    pub new_min_stratum: i32,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, ChronySerialize)]
pub struct ModifyPollTarget {
    pub address: ChronyAddr,
    pub new_poll_target: i32,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, ChronySerialize)]
pub struct ModifyMaxUpdateSkew {
    pub new_max_update_skew: ChronyFloat,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, ChronySerialize)]
pub struct ModifyMakeStep {
    pub limit: i32,
    pub threshold: ChronyFloat,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, ChronySerialize)]
pub struct Logon {
    pub ts: SystemTime,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, ChronySerialize)]
pub struct SetTime {
    pub ts: SystemTime,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, ChronySerialize)]
pub struct Local {
    pub on_off: i32,
    pub stratum: i32,
    pub distance: ChronyFloat,
    pub orphan: i32,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, ChronySerialize)]
pub struct Manual {
    pub option: i32,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, ChronySerialize)]
pub struct SourceData {
    pub index: i32,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, ChronySerialize)]
pub struct AllowDeny {
    pub ip: ChronyAddr,
    pub subnet_bits: i32,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, ChronySerialize)]
pub struct AcCheck {
    pub ip: ChronyAddr,
}

#[repr(u32)]
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
pub enum AddSrcType {
    Server = 1,
    Peer = 2,
    Pool = 3,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, ChronySerialize)]
pub struct NtpSource {
    pub src_type: AddSrcType,
    pub name: [u8; 256],
    pub port: u32,
    pub minpoll: i32,
    pub maxpoll: i32,
    pub presend_minpoll: i32,
    pub min_stratum: i32,
    pub poll_target: u32,
    pub version: u32,
    pub max_sources: u32,
    pub min_samples: u32,
    pub max_samples: u32,
    pub authkey: u32,
    pub nts_port: u32,
    pub max_delay: ChronyFloat,
    pub max_delay_ratio: ChronyFloat,
    pub max_delay_dev_ratio: ChronyFloat,
    pub min_delay: ChronyFloat,
    pub asymmetry: ChronyFloat,
    // In the chrony sources, `flags` is 32 bits in requests and 16 bits in replies.
    // So that we can use the same data type in both messages, we make it 16 bits
    // everywhere and treat the two unused high bytes in the request as padding.
    #[pad = 2]
    pub offset: ChronyFloat,
    pub flags: SourceFlags,
    pub filter_length: i32,
    #[pad = 8]
    pub cert_set: i32,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, ChronySerialize)]
pub struct DelSource {
    pub ip_addr: ChronyAddr,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, ChronySerialize)]
pub struct DFreq {
    pub dfreq: ChronyFloat,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, ChronySerialize)]
pub struct DOffset {
    pub doffset: ChronyFloat,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, ChronySerialize)]
pub struct SourceStats {
    pub index: u32,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, ChronySerialize)]
pub struct ClientAccessesByIndex {
    pub first_index: u32,
    pub n_clients: u32,
    pub min_hits: u32,
    pub reset: u32,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, ChronySerialize)]
pub struct ManualDelete {
    pub index: u32,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, ChronySerialize)]
pub struct ReselectDistance {
    pub distance: ChronyFloat,
}

#[repr(i32)]
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
pub enum SmoothTimeOption {
    Reset,
    Activate,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, ChronySerialize)]
pub struct SmoothTime {
    pub option: SmoothTimeOption,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, ChronySerialize)]
pub struct NtpData {
    pub ip_addr: ChronyAddr,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, ChronySerialize)]
pub struct NtpSourceName {
    pub ip_addr: ChronyAddr,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, ChronySerialize)]
pub struct AuthData {
    pub ip_addr: ChronyAddr,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, ChronySerialize)]
pub struct SelectData {
    pub index: u32,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, ChronyMessage)]
pub enum RequestBody {
    Null,
    Online(Online),
    Offline(Offline),
    Burst(Burst),
    ModifyMinPoll(ModifyMinPoll),
    ModifyMaxPoll(ModifyMaxPoll),
    #[pad = 4]
    Dump,
    ModifyMaxDelay(ModifyMaxDelay),
    ModifyMaxDelayRatio(ModifyMaxDelayRatio),
    ModifyMaxUpdateSkew(ModifyMaxUpdateSkew),
    Logon(Logon),
    SetTime(SetTime),
    #[cmd = 13]
    Manual(Manual),
    NSources,
    SourceData(SourceData),
    Rekey,
    Allow(AllowDeny),
    AllowAll(AllowDeny),
    Deny(AllowDeny),
    DenyAll(AllowDeny),
    CmdAllow(AllowDeny),
    CmdAllowAll(AllowDeny),
    CmdDeny(AllowDeny),
    CmdDenyAll(AllowDeny),
    AcCheck(AcCheck),
    CmdAcCheck(AcCheck),
    #[cmd = 29]
    DelSource(DelSource),
    WriteRtc,
    DFreq(DFreq),
    #[cmd = 33]
    Tracking,
    SourceStats(SourceStats),
    RtcReport,
    TrimRtc,
    CycleLogs,
    #[cmd = 41]
    ManualList,
    ManualDelete(ManualDelete),
    MakeStep,
    Activity,
    ModifyMinStratum(ModifyMinStratum),
    ModifyPollTarget(ModifyPollTarget),
    ModifyMaxDelayDevRatio(ModifyMaxDelayDevRatio),
    Reselect,
    ReselectDistance(ReselectDistance),
    ModifyMakeStep(ModifyMakeStep),
    Smoothing,
    SmoothTime(SmoothTime),
    Refresh,
    ServerStats,
    #[cmd = 56]
    Local2(Local),
    NtpData(NtpData),
    #[cmd = 62]
    Shutdown,
    OnOffline,
    AddSource(NtpSource),
    NtpSourceName(NtpSourceName),
    ResetSources,
    AuthData(AuthData),
    ClientAccessesByIndex3(ClientAccessesByIndex),
    SelectData(SelectData),
    ReloadSources,
    DOffset2(DOffset),
}

impl RequestBody {
    pub(crate) fn reply_body_length(&self) -> usize {
        match self {
            Self::Null => 0,
            Self::Online(_) => 0,
            Self::Offline(_) => 0,
            Self::Burst(_) => 0,
            Self::ModifyMinPoll(_) => 0,
            Self::ModifyMaxPoll(_) => 0,
            Self::Dump => 0,
            Self::ModifyMaxDelay(_) => 0,
            Self::ModifyMaxDelayRatio(_) => 0,
            Self::ModifyMaxUpdateSkew(_) => 0,
            Self::Logon(_) => 0,
            Self::SetTime(_) => reply::ManualTimestamp::length(),
            Self::Manual(_) => 0,
            Self::NSources => reply::NSources::length(),
            Self::SourceData(_) => reply::SourceData::length(),
            Self::Rekey => 0,
            Self::Allow(_) => 0,
            Self::AllowAll(_) => 0,
            Self::Deny(_) => 0,
            Self::DenyAll(_) => 0,
            Self::CmdAllow(_) => 0,
            Self::CmdAllowAll(_) => 0,
            Self::CmdDeny(_) => 0,
            Self::CmdDenyAll(_) => 0,
            Self::AcCheck(_) => 0,
            Self::CmdAcCheck(_) => 0,
            Self::DelSource(_) => 0,
            Self::WriteRtc => 0,
            Self::DFreq(_) => 0,
            Self::Tracking => reply::Tracking::length(),
            Self::SourceStats(_) => reply::SourceStats::length(),
            Self::RtcReport => reply::Rtc::length(),
            Self::TrimRtc => 0,
            Self::CycleLogs => 0,
            Self::ManualList => reply::ManualList::length(),
            Self::ManualDelete(_) => 0,
            Self::MakeStep => 0,
            Self::Activity => reply::Activity::length(),
            Self::ModifyMinStratum(_) => 0,
            Self::ModifyPollTarget(_) => 0,
            Self::ModifyMaxDelayDevRatio(_) => 0,
            Self::Reselect => 0,
            Self::ReselectDistance(_) => 0,
            Self::ModifyMakeStep(_) => 0,
            Self::Smoothing => reply::Smoothing::length(),
            Self::SmoothTime(_) => 0,
            Self::Refresh => 0,
            Self::ServerStats => reply::ServerStats4::length(),
            Self::Local2(_) => 0,
            Self::NtpData(_) => reply::NtpData::length(),
            Self::Shutdown => 0,
            Self::OnOffline => 0,
            Self::AddSource(_) => 0,
            Self::NtpSourceName(_) => reply::NtpSourceName::length(),
            Self::ResetSources => 0,
            Self::AuthData(_) => reply::AuthData::length(),
            Self::ClientAccessesByIndex3(_) => reply::ClientAccessesByIndex::length(),
            Self::SelectData(_) => reply::SelectData::length(),
            Self::ReloadSources => 0,
            Self::DOffset2(_) => 0,
        }
    }
}

/// A request to Chrony
#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash)]
pub struct Request {
    /// Sequence number
    pub sequence: u32,
    /// Attempt number
    pub attempt: u16,
    /// Body of the request
    pub body: RequestBody,
}

impl Request {
    pub fn length(&self) -> usize {
        std::cmp::max(
            self.body.body_length() + REQUEST_HEADER_LENGTH,
            self.body.reply_body_length() + REPLY_HEADER_LENGTH,
        )
    }

    pub fn serialize<B: BufMut>(&self, buf: &mut B) {
        let cmd = self.body.cmd();
        let body_length = self.body.body_length();
        let reply_body_length = self.body.reply_body_length();
        let padding_length = std::cmp::max(
            body_length + REQUEST_HEADER_LENGTH,
            reply_body_length + REPLY_HEADER_LENGTH,
        ) - REQUEST_HEADER_LENGTH
            - body_length;

        buf.put_u8(6); //Version
        buf.put_u8(1); //Packet type = request
        buf.put_u8(0); //Reserved
        buf.put_u8(0); //Reserved
        buf.put_u16(cmd);
        buf.put_u16(self.attempt);
        buf.put_u32(self.sequence);
        buf.put_u32(0); //Padding
        buf.put_u32(0); //Padding
        self.body.serialize_body(buf);
        buf.put_slice(vec![0u8; padding_length].as_slice());
    }

    pub fn deserialize<B: Buf>(buf: &mut B) -> Result<Self, DeserializationError> {
        if buf.remaining() < REQUEST_HEADER_LENGTH {
            return Err(DeserializationError::new("message too short"));
        }
        if buf.get_u8() != 6 {
            //Version
            return Err(DeserializationError::new("unsupported version"));
        }

        if buf.get_u8() != 1 {
            //Packet type
            return Err(DeserializationError::new("wrong packet type"));
        }

        buf.get_u8(); //Reserved
        buf.get_u8(); //Reserved
        let cmd = buf.get_u16();
        let attempt = buf.get_u16();
        let sequence = buf.get_u32();
        buf.get_u32(); //Padding
        buf.get_u32(); //Padding
        let body = RequestBody::deserialize_body(cmd, buf)?;

        let body_length = body.body_length();
        let reply_body_length = body.reply_body_length();
        let padding_length = std::cmp::max(body_length, reply_body_length) - body_length;
        if buf.remaining() < padding_length {
            return Err(DeserializationError::new("insufficient padding"));
        }
        buf.advance(padding_length);
        Ok(Self {
            sequence,
            attempt,
            body,
        })
    }

    pub fn cmd(&self) -> u16 {
        self.body.cmd()
    }
}

pub fn increment_attempt(buf: &mut [u8]) {
    let old_attempt = u16::from_be_bytes(buf[6..8].try_into().unwrap());
    let new_attempt = old_attempt + 1;
    buf[6..8].copy_from_slice(&new_attempt.to_be_bytes());
}
