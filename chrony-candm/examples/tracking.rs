// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: GPL-2.0-only

use chrono::Utc;
use chrony_candm::{query_uds, Client, ClientOptions, UnixDatagramClient};
use chrony_candm::{reply::ReplyBody, request::RequestBody};
use std::{
    net::{Ipv6Addr, SocketAddr, SocketAddrV6},
    str::FromStr,
};
use tokio::runtime::Handle;

use clap::{Parser, ValueEnum};

#[derive(Parser, Debug)]
struct Args {
    /// type of connection to use
    client_type: ClientType,
}

#[derive(Debug, ValueEnum, Clone, Copy)]
enum ClientType {
    Uds,
    UdpV6,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args = Args::parse();
    let request_body = RequestBody::Tracking;

    let reply = match args.client_type {
        ClientType::Uds => {
            println!("Using UDS");
            let mut client = UnixDatagramClient::new().await.unwrap();
            client.query(request_body, ClientOptions::default()).await.unwrap()
        }
        ClientType::UdpV6 => {
            println!("Using UDPv6");
            let client = Client::spawn(&Handle::current(), Default::default());
            let server_addr = SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from_str("::1").unwrap(),
                323,
                0,
                0,
            ));
            client.query(request_body, server_addr).await.unwrap()
        }
    };

    println!("Status: {:?}", reply.status);
    if let ReplyBody::Tracking(body) = reply.body {
        println!("Reference ID: {}", body.ref_id);
        println!("Source IP: {}", body.ip_addr);
        println!("Stratum: {}", body.stratum);
        println!(
            "Ref time: {}",
            chrono::DateTime::<Utc>::from(body.ref_time)
                .to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)
        );
        let current_correction: f64 = body.current_correction.into();
        println!(
            "System time: {:.9} seconds {} of NTP time",
            current_correction.abs(),
            if current_correction.is_sign_negative() {
                "fast"
            } else {
                "slow"
            }
        );
        println!("Last offset: {:+.9} seconds", body.last_offset);
        println!("RMS offset: {:.9} seconds", body.rms_offset);
        let freq_ppm: f64 = body.freq_ppm.into();
        println!(
            "Frequency: {:.3} ppm {}",
            freq_ppm.abs(),
            if freq_ppm.is_sign_negative() {
                "slow"
            } else {
                "fast"
            }
        );
        println!("Residual freq: {:+.3} ppm", body.resid_freq_ppm);
        println!("Skew: {:.3} ppm", body.skew_ppm);
        println!("Root delay: {:.9} seconds", body.root_delay);
        println!("Root dispersion: {:.9} seconds", body.root_dispersion);
        println!("Update interval: {:.1} seconds", body.last_update_interval);
        println!(
            "Leap status: {}",
            match body.leap_status {
                0 => "Normal",
                1 => "Insert",
                2 => "Delete",
                3 => "Unsynchronized",
                _ => "Invalid",
            }
        )
    }
}
