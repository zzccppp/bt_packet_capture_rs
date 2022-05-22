use std::sync::Arc;
use std::time::Duration;

use crate::flow::Flow;
use crate::parser::{SimpleDumpCodec, SimpleParsedPacket, TcpFlowParser, UdpFlowParser};
use flow::FlowCollections;
use futures::StreamExt;
use inquire::{Select, Text};
use parser::start_new_stream;
use pcap::stream::PacketCodec;
use pcap::{Capture, Device};
use tokio::sync::{mpsc, Mutex};
use tokio::time::sleep;
use tokio::{select, time};
use tracing::info;

pub mod flow;
pub mod parser;
pub mod bencode;

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
    let mut filepath = "".to_string();
    let is_read_file = index == device_list_name.len() - 1;

    if is_read_file {
        // select the file option
        filepath = Text::new("Enter pcap file path").prompt().unwrap();
        info!("use the file {}", filepath);
    }

    // let index = 0;

    //start the log
    tracing_subscriber::fmt::init();

    let (tcp_tx, tcp_rx) = mpsc::channel::<SimpleParsedPacket>(1024);
    let (udp_tx, udp_rx) = mpsc::channel::<SimpleParsedPacket>(1024);
    let (tcp_flow_tx, tcp_flow_rx) = mpsc::channel::<Flow>(1024);
    let (udp_flow_tx, udp_flow_rx) = mpsc::channel::<Flow>(1024);

    let h1 = rt.spawn(async move {
        //receive the tcp packets to analysis flow
        let mut tcp_rx = tcp_rx;
        let mut udp_rx = udp_rx;
        let mut tcp_flow_tx = tcp_flow_tx;
        let mut udp_flow_tx = udp_flow_tx;
        let mut tcp_flow_collections = FlowCollections::new();
        let mut udp_flow_collections = FlowCollections::new();
        let mut interval = time::interval(Duration::from_millis(1000));
        loop {
            select! {
                Some(tcp_recv) = tcp_rx.recv() => {
                    tcp_flow_collections.insert_packet(tcp_recv);
                },
                Some(udp_recv) = udp_rx.recv() => {
                    udp_flow_collections.insert_packet(udp_recv);
                },
                _ = interval.tick() => {
                    let flows = tcp_flow_collections.clear_flows();
                    for (_k, v) in flows {
                        tcp_flow_tx.send(v).await.unwrap();
                    }
                    let flows = udp_flow_collections.clear_flows();
                    for (_k, v) in flows {
                        udp_flow_tx.send(v).await.unwrap();
                    }
                }
                else => {break;},
            };
        }
    });

    let h2 = rt.spawn(async move {
        let mut tcp_flow_rx = tcp_flow_rx;
        let mut parser = TcpFlowParser::new();
        while let Some(flow) = tcp_flow_rx.recv().await {
            parser.parse_flow(flow);
        }
    });
    let h3 = rt.spawn(async move {
        let mut udp_flow_rx = udp_flow_rx;
        let mut parser = UdpFlowParser::new();
        while let Some(flow) = udp_flow_rx.recv().await {
            parser.parse_flow(flow);
        }
    });

    if is_read_file {
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
        h2.await.unwrap();
        h3.await.unwrap();
    });

    info!("Finished analysis packets");
}
