#![allow(non_snake_case)]

use std::path::PathBuf;

use clap::Parser;
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, NetworkInterface};
use pnet::packet::arp::ArpPacket;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::Packet;

#[derive(Parser)]
struct Cli {
    /// Set Interface to Sniff
    interface_name: Option<String>,

    /// Set Output File
    #[arg(short, long, value_name = "FILE")]
    output: Option<PathBuf>,

    /// List Interfaces
    #[arg(short, long)]
    list: bool,

    /// Verbose Output
    #[arg(short, long)]
    verbose: bool,
}

fn main() {
    let cli = Cli::parse();
    let interfaces = datalink::interfaces();

    if cli.list {
        print!("{:<50} {:<25}", "Name", "Mac");
        if cli.verbose {
            print!("{:<35}{:<25}", "Description", "IPs")
        }
        println!();

        interfaces.clone().into_iter().for_each(|iface| {
            if let Some(mac) = iface.mac {
                print!("{:<50} {:<25}", iface.name, mac.to_string());
            } else {
                print!("{:<50} {:<25}", iface.name, "");
            }
            if cli.verbose {
                print!("{:<35}", iface.description);
                iface
                    .ips
                    .iter()
                    .enumerate()
                    .for_each(|(index, ip)| if index >= 1 {print!(" - {}", ip)} else {print!("{}", ip)});
            }
            println!();
        });
    }

    if let Some(interface_name) = cli.interface_name.as_deref() {
        let interface = interfaces
            .clone()
            .into_iter()
            .filter(|iface: &NetworkInterface| iface.name == interface_name)
            .next()
            .unwrap_or_else(|| panic!("No Network Interface: {}", interface_name));

        // Create a new channel, dealing with layer 2 packets
        let (_tx, mut rx) = match datalink::channel(&interface, Default::default()) {
            Ok(Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => panic!("Unhandled channel type"),
            Err(e) => panic!(
                "An error occurred when creating the datalink channel: {}",
                e
            ),
        };

        loop {
            match rx.next() {
                Ok(packet) => {
                    let packet = EthernetPacket::new(packet).unwrap();

                    if packet.get_ethertype() == EtherTypes::Arp {
                        let header = ArpPacket::new(packet.payload());

                        if let Some(header) = header {
                            println!(
                                "[{}]: ARP packet: {}({}) > {}({}); operation: {:?}",
                                interface_name,
                                packet.get_source(),
                                header.get_sender_proto_addr(),
                                packet.get_destination(),
                                header.get_target_proto_addr(),
                                header.get_operation()
                            );
                        }
                    }
                }
                Err(e) => {
                    // If an error occurs, we can handle it here
                    panic!("An error occurred while reading: {}", e);
                }
            }
        }
    }
    if let Some(file) = cli.output.as_deref() {
        println!("Output File: {0}", file.display());
    }
}
