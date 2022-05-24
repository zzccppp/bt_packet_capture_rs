use std::net::{Ipv4Addr, Ipv6Addr};

use etherparse::SlicedPacket;
use pcap::stream::{PacketCodec, PacketStream};
use pcap::{Active, Capture, Device, Error, Packet};
use tracing::{info, warn};

use crate::flow::{Flow, UdpPeerFlow};

#[derive(Debug, Clone, PartialEq, PartialOrd, Eq, Ord)]
pub struct TimeVal {
    pub tv_sec: i64,
    pub tv_usec: i64,
}

#[derive(Debug, Clone)]
pub struct SimpleParsedPacket {
    pub payload: Vec<u8>,
    pub info: PacketQuadruple,
    pub timeval: TimeVal,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum InetAddr {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TransportProtocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone)]
pub struct PacketQuadruple {
    pub src_port: u16,
    pub dst_port: u16,
    pub src_ip: InetAddr,
    pub dst_ip: InetAddr,
    pub transport: TransportProtocol,
}

impl PacketQuadruple {
    pub fn get_src_dst_tuple(&self) -> (InetAddr, u16, InetAddr, u16) {
        (
            self.src_ip.clone(),
            self.src_port,
            self.dst_ip.clone(),
            self.dst_port,
        )
    }

    pub fn get_dst_src_tuple(&self) -> (InetAddr, u16, InetAddr, u16) {
        (
            self.dst_ip.clone(),
            self.dst_port,
            self.src_ip.clone(),
            self.src_port,
        )
    }

    pub fn from_sliced_packet(p: &SlicedPacket) -> Result<Self, &'static str> {
        let mut inf = Self {
            src_port: 0,
            dst_port: 0,
            src_ip: InetAddr::Ipv4(Ipv4Addr::UNSPECIFIED),
            dst_ip: InetAddr::Ipv4(Ipv4Addr::UNSPECIFIED),
            transport: TransportProtocol::Tcp,
        };
        match &p.ip {
            Some(e) => match e {
                etherparse::InternetSlice::Ipv4(header, _ext) => {
                    inf.src_ip = InetAddr::Ipv4(header.source_addr());
                    inf.dst_ip = InetAddr::Ipv4(header.destination_addr());
                }
                etherparse::InternetSlice::Ipv6(header, _ext) => {
                    inf.src_ip = InetAddr::Ipv6(header.source_addr());
                    inf.dst_ip = InetAddr::Ipv6(header.destination_addr());
                }
            },
            None => {
                // println!("{:?}", p);
                return Err("Unknown Ip Layer");
            }
        }
        match &p.transport {
            Some(e) => match e {
                etherparse::TransportSlice::Udp(udp) => {
                    inf.src_port = udp.source_port();
                    inf.dst_port = udp.destination_port();
                    inf.transport = TransportProtocol::Udp;
                }
                etherparse::TransportSlice::Tcp(tcp) => {
                    inf.src_port = tcp.source_port();
                    inf.dst_port = tcp.destination_port();
                    inf.transport = TransportProtocol::Tcp;
                }
                etherparse::TransportSlice::Unknown(_) => {
                    // println!("{:?}", p);
                    return Err("Unknown Transport Layer");
                }
            },
            None => {
                // println!("{:?}", p);
                return Err("Unknown Transport Layer");
            }
        }
        Ok(inf)
    }
}

pub struct SimpleDumpCodec {}

impl PacketCodec for SimpleDumpCodec {
    type Type = SimpleParsedPacket;

    fn decode(&mut self, packet: Packet) -> Result<Self::Type, Error> {
        let data: &[u8] = &packet;
        let sliced = SlicedPacket::from_ethernet(data);
        if let Ok(sliced) = sliced {
            let payload = sliced.payload;
            let info = PacketQuadruple::from_sliced_packet(&sliced);
            if let Ok(info) = info {
                Ok(SimpleParsedPacket {
                    payload: payload.to_vec(),
                    info,
                    timeval: TimeVal {
                        tv_sec: packet.header.ts.tv_sec as i64,
                        tv_usec: packet.header.ts.tv_usec as i64,
                    },
                })
            } else {
                let error = info.unwrap_err();
                // warn!("{}", error);
                Err(Error::PcapError(error.to_string()))
            }
        } else {
            // warn!("Failed to decode packet {:?}", packet);
            Err(Error::PcapError("Failed to decode packet".to_string()))
        }
        // Ok(format!("{:?}", packet))
    }
}

pub async fn start_new_stream(device: Device) -> PacketStream<Active, SimpleDumpCodec> {
    info!("Using device {}", device.name);

    let cap = Capture::from_device(device)
        .unwrap()
        .buffer_size(1024 * 1024 * 64)
        .immediate_mode(true)
        .open()
        .unwrap()
        .setnonblock()
        .unwrap();
    let stream = cap.stream(SimpleDumpCodec {}).unwrap();
    stream
}

#[derive(Debug, Clone)]
pub struct TcpFlowParser {}

impl TcpFlowParser {
    pub fn new() -> Self {
        Self {}
    }

    pub fn parse_flow(&mut self, flow: Flow) {}
}

#[derive(Debug, Clone)]
pub struct UdpFlowParser {
    pub peer_flows: Vec<UdpPeerFlow>,
}

impl UdpFlowParser {
    pub fn new() -> Self {
        Self { peer_flows: vec![] }
    }

    pub fn parse_flow(&mut self, flow: Flow) {
        let mut flow = flow;
        flow.packets.sort_by(|x, y| {
            return x.timeval.cmp(&y.timeval);
        });
        for p in flow.packets.iter() {
            // 这里需要检测不同的特征，如果特征成立，则送去分析Bt协议
            // TODO: 字符串匹配 0x13 BitTorrent protocol

            // 特征：UDP报文直接承载bencode流
            let re = bende::decode::<bende::Value>(p.payload.as_slice());
            // if there is valid bencode udp packet
            if let Ok(_) = re {
                let peer_flow = UdpPeerFlow::from_flow(&flow);
                // info!("{:?}", peer_flow);
                self.peer_flows.push(peer_flow);
                return;
            }
        }
    }
}
