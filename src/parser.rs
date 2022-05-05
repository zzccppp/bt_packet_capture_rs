use std::net::{Ipv4Addr, Ipv6Addr};

use etherparse::SlicedPacket;
use pcap::stream::{PacketCodec, PacketStream};
use pcap::{Active, Capture, Device, Error, Packet};
use tracing::warn;

#[derive(Debug, Clone, PartialEq, PartialOrd)]
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

#[derive(Debug, Clone)]
pub enum InetAddr {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
}

#[derive(Debug, Clone)]
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
                        tv_sec: packet.header.ts.tv_sec,
                        tv_usec: packet.header.ts.tv_usec,
                    },
                })
            } else {
                let error = info.unwrap_err();
                warn!("{}", error);
                Err(Error::PcapError(error.to_string()))
            }
        } else {
            warn!("Failed to decode packet {:?}", packet);
            Err(Error::PcapError("Failed to decode packet".to_string()))
        }
        // Ok(format!("{:?}", packet))
    }
}

pub async fn start_new_stream(device: Device) -> PacketStream<Active, SimpleDumpCodec> {
    println!("Using device {}", device.name);

    let cap = Capture::from_device(device)
        .unwrap()
        .immediate_mode(true)
        .open()
        .unwrap()
        .setnonblock()
        .unwrap();
    let stream = cap.stream(SimpleDumpCodec {}).unwrap();
    stream
}