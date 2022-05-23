use std::collections::HashMap;

use tracing::info;

use crate::parser::{InetAddr, PacketQuadruple, SimpleParsedPacket, TimeVal};

#[derive(Debug)]
pub struct FlowCollections {
    flows: HashMap<(InetAddr, u16, InetAddr, u16), Flow>,
}

impl FlowCollections {
    pub fn new() -> Self {
        Self {
            flows: HashMap::new(),
        }
    }

    pub fn insert_packet(&mut self, packet: SimpleParsedPacket) {
        let info = packet.info.clone();
        if let Some(e) = self.flows.get_mut(&info.get_src_dst_tuple()) {
            e.insert_packet(packet);
            return;
        }
        if let Some(e) = self.flows.get_mut(&info.get_dst_src_tuple()) {
            e.insert_packet(packet);
            return;
        }
        let mut flow = Flow::new(&info);
        flow.insert_packet(packet);
        self.flows.insert(info.get_src_dst_tuple(), flow);
    }

    pub fn clear_flows(
        &mut self,
    ) -> std::collections::hash_map::Drain<'_, (InetAddr, u16, InetAddr, u16), Flow> {
        return self.flows.drain();
    }
}

#[derive(Debug, Clone)]
pub struct Flow {
    pub packets: Vec<SimpleParsedPacket>,
    pub info: PacketQuadruple,
}

impl Flow {
    pub fn new(info: &PacketQuadruple) -> Self {
        Self {
            packets: Vec::new(),
            info: info.clone(),
        }
    }

    pub fn insert_packet(&mut self, packet: SimpleParsedPacket) {
        self.packets.push(packet);
    }
}

#[derive(Debug, Clone)]
pub enum UdpPeerPacketEnum {
    RawBencode(bende::Value),
    Utp,
    Other,
}

#[derive(Debug, Clone)]
pub struct UtpPacket {
    pub type_ver: u8,
    pub connid: u16,
    pub payload: UtpPayload,
}

impl UtpPacket {
    
}

#[derive(Debug, Clone)]
pub enum UtpPayload {
    Bittorrent(BittorrentPacket),
    Other(Vec<u8>),
}

#[derive(Debug, Clone)]
pub struct BittorrentPacket {}

#[derive(Debug, Clone)]
pub struct UdpPeerPacket {
    pub data: UdpPeerPacketEnum,
    pub timeval: TimeVal,
    pub info: PacketQuadruple,
}

impl UdpPeerPacket {
    pub fn from_simple_packet(p: &SimpleParsedPacket) -> Self {
        let bencode = bende::decode::<bende::Value>(p.payload.as_slice());
        let mut data = UdpPeerPacketEnum::Other;
        if let Ok(val) = bencode {
            info!("{:?}", val);
            data = UdpPeerPacketEnum::RawBencode(val);
        } else {
            // try to parse the utp protocol
            let slice = p.payload.as_slice();
            /* version 1 header:
            0       4       8               16              24              32
            +-------+-------+---------------+---------------+---------------+
            | type  | ver   | extension     | connection_id                 |
            +-------+-------+---------------+---------------+---------------+
            | timestamp_microseconds                                        |
            +---------------+---------------+---------------+---------------+
            | timestamp_difference_microseconds                             |
            +---------------+---------------+---------------+---------------+
            | wnd_size                                                      |
            +---------------+---------------+---------------+---------------+
            | seq_nr                        | ack_nr                        |
            +---------------+---------------+---------------+---------------+
            All fields are in network byte order (big endian).
                            */
            // type and ver is 0x01 0x11 0x21 0x31 0x41
            if slice.len() > 20 {
                // greater than utp header length
                match slice[0] {
                    0x01 | 0x11 | 0x21 | 0x31 | 0x41 => {}
                    _ => {}
                }
            }
        }
        Self {
            data,
            timeval: p.timeval.clone(),
            info: p.info.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct UdpPeerFlow {
    pub packets: Vec<UdpPeerPacket>,
    pub info: PacketQuadruple,
    // start_timeval end_timeval
}

impl UdpPeerFlow {
    pub fn from_flow(flow: &Flow) -> Self {
        let mut peer_packets = vec![];
        for p in flow.packets.iter() {
            peer_packets.push(UdpPeerPacket::from_simple_packet(p));
        }
        Self {
            packets: peer_packets,
            info: flow.info.clone(),
        }
    }
}
