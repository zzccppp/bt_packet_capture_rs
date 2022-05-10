use std::sync::Arc;
use std::time::Duration;

use crate::parser::{SimpleDumpCodec, SimpleParsedPacket};
use flow::FlowCollections;
use futures::StreamExt;
use inquire::{Select, Text};
use parser::start_new_stream;
use pcap::stream::PacketCodec;
use pcap::{Capture, Device};
use tokio::select;
use tokio::sync::{mpsc, Mutex};
use tokio::time::sleep;
use tracing::info;

pub mod flow;
pub mod parser;

fn main() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let device_list = Device::list().unwrap();

    let mut device_list_name: Vec<String> =
        device_list.iter().map(|dev| dev.name.clone()).collect();
    device_list_name.push("Read Pcap File".to_string());

    let sel = Select::new("Select a device", device_list_name.clone())
        .prompt()
        .unwrap();

    let index = device_list_name.iter().position(|s| *s == sel).unwrap();
    // let index = 0;

    //start the log
    tracing_subscriber::fmt::init();

    let (tcp_tx, tcp_rx) = mpsc::channel::<SimpleParsedPacket>(1024);
    let (udp_tx, udp_rx) = mpsc::channel::<SimpleParsedPacket>(1024);

    let h1 = rt.spawn(async move {
        //receive the tcp packets to analysis flow
        let mut tcp_rx = tcp_rx;
        let mut udp_rx = udp_rx;
        let mut tcp_flow_collections = FlowCollections::new();
        let mut udp_flow_collections = FlowCollections::new();
        loop {
            select! {
                Some(tcp_recv) = tcp_rx.recv() => {
                    tcp_flow_collections.insert_packet(tcp_recv);
                },
                Some(udp_recv) = udp_rx.recv() => {
                    udp_flow_collections.insert_packet(udp_recv);
                },
                else => {break;},
            };
        }
        println!("tcp_flow: {:?}", tcp_flow_collections);
    });

    let analysis_handle = rt.spawn(async move {
        sleep(Duration::from_millis(1000)).await;
    });

    if index == device_list_name.len() - 1 {
        // select the file option
        let filepath = Text::new("Enter pcap file path").prompt().unwrap();
        info!("use the file {}", filepath);

        rt.block_on(async move {
            let mut cap = Capture::from_file(filepath).unwrap();
            while let Ok(pcap) = cap.next() {
                let mut codec = SimpleDumpCodec {};
                if let Ok(s) = codec.decode(pcap) {
                    match s.info.transport {
                        parser::TransportProtocol::Tcp => {
                            tcp_tx.send(s).await.unwrap();
                        }
                        parser::TransportProtocol::Udp => {
                            udp_tx.send(s).await.unwrap();
                        }
                    }
                }
            }
        });
        info!("Finished sending packets");
    } else {
        let mut stream = rt.block_on(start_new_stream(device_list[index].clone()));

        rt.block_on(async {
            while let Some(packet) = stream.next().await {
                if let Ok(s) = packet {
                    match s.info.transport {
                        parser::TransportProtocol::Tcp => {
                            tcp_tx.send(s).await.unwrap();
                        }
                        parser::TransportProtocol::Udp => {
                            udp_tx.send(s).await.unwrap();
                        }
                    }
                }
            }
        });
    }

    rt.block_on(async {
        h1.await.unwrap();
        // h2.await.unwrap();
        analysis_handle.await.unwrap();
    });

    info!("Finished analysis packets");
}
