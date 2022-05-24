use std::{cmp::Ordering, collections::HashMap, hash::Hash, io::Cursor};

use bytes::{Buf, BufMut, BytesMut};
use serde::Serialize;
use tracing::{info, instrument};

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
    Utp(UtpPacket),
    Other,
}

#[derive(Debug, Clone)]
pub struct UtpPacket {
    pub type_ver: u8,
    pub connid: u16,
    pub payload: Vec<u8>,
    pub seq: u16,
}

impl UtpPacket {
    pub fn new(type_ver: u8, connid: u16, seq: u16, payload: &[u8]) -> Self {
        Self {
            type_ver,
            connid,
            seq,
            payload: payload.to_vec(),
        }
    }
}

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
            // info!("{:?}", val);
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
                    0x01 | 0x11 | 0x21 | 0x31 | 0x41 => {
                        let conn_id_slice = [slice[2], slice[3]];
                        let mut buf = Cursor::new(conn_id_slice);
                        let conn_id = buf.get_u16();
                        let payload_start = if slice[1] == 0 {
                            20usize
                        } else {
                            // process the extensions
                            /*
                            0               8               16
                            +---------------+---------------+
                            | extension     | len           |
                            +---------------+---------------+
                            */
                            let mut temp = 20usize;
                            let len = slice.len();
                            loop {
                                if len < temp + 2 {
                                    temp = 0;
                                    break;
                                }
                                if len < temp + 2 + slice[temp + 1] as usize {
                                    temp = 0;
                                    break;
                                }
                                if slice[temp] == 0 {
                                    temp += 2 + slice[temp + 1] as usize;
                                    break;
                                }
                                temp += 2 + slice[temp + 1] as usize;
                            }
                            temp
                        };
                        let seq_slice = [slice[16], slice[17]];
                        let mut buf = Cursor::new(seq_slice);
                        let seq = buf.get_u16();
                        if payload_start != 0 {
                            data = UdpPeerPacketEnum::Utp(UtpPacket::new(
                                slice[0],
                                conn_id,
                                seq,
                                &slice[payload_start..],
                            ));
                        }
                    }
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
pub enum BitTorrentMessage {
    HandShake {
        info_hash: Vec<u8>,
        peer_id: Vec<u8>,
    },
    Choke,         //no payload
    Unchoke,       //no payload
    Interested,    //no payload
    NotInterested, //no payload
    Have {
        idx: u32,
    },
    Bitfield {
        bitfield: Vec<u8>,
    }, //not interested
    Request {
        piece_index: u32,
        begin_piece_offset: u32,
        piece_length: u32,
    },
    Piece {
        piece_index: u32,
        begin_piece_offset: u32,
        data: Vec<u8>,
    },
    Cancel {
        piece_index: u32,
        begin_piece_offset: u32,
        piece_length: u32,
    },
    Port, //DHT Extension 0x09
    /*
        0x0D   suggest
        0x0E   have all
        0x0F   have none
        0x10   reject request
        0x11   allowed fast
    */
    Suggest,
    HaveAll,
    HaveNone,
    RejectRequest,
    AllowedFast,
    // 0x14
    Extended {
        data: Vec<u8>,
    },
}

#[derive(Debug, Clone)]
pub struct BittorrentFlow {
    pub conn_id1: u16,
    pub conn_id2: u16,
    pub messages1: Vec<BitTorrentMessage>,
    pub messages2: Vec<BitTorrentMessage>,
    pub info_hash: Option<Vec<u8>>, // 如果没有，则证明没有找到握手信息
}

pub fn parse_utp_to_bittorrent(packets: Vec<&UdpPeerPacket>) {
    let mut buf = BytesMut::with_capacity(64);
    for &p in packets.iter() {}
}

#[derive(Debug, Clone)]
pub struct UdpPeerFlow {
    pub packets: Vec<UdpPeerPacket>,
    pub info: PacketQuadruple,
    // start_timeval end_timeval
    pub utp_binary_flow: HashMap<u16, (BytesMut, BytesMut)>,
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
            utp_binary_flow: HashMap::new(),
        }
    }

    pub fn add_packets(&mut self, flow: &Flow) {
        for p in flow.packets.iter() {
            self.packets.push(UdpPeerPacket::from_simple_packet(p));
        }
        self.packets.sort_by(|x, y| x.timeval.cmp(&y.timeval));
    }

    // #[instrument]
    pub fn analysis(&mut self) {
        let utp_packet: Vec<&UdpPeerPacket> = self
            .packets
            .iter()
            .filter(|x| match x.data {
                UdpPeerPacketEnum::Utp(_) => true,
                _ => false,
            })
            .collect();
        if utp_packet.len() == 0 {
            // 筛选出有价值的utp对话
            return;
        }
        let mut conn_ids: Vec<u16> = utp_packet
            .iter()
            .map(|x| {
                if let UdpPeerPacketEnum::Utp(e) = &x.data {
                    return e.connid;
                }
                return 0;
            })
            .collect();
        conn_ids.sort();
        conn_ids.dedup();
        if conn_ids.is_empty() || conn_ids.len() < 2 {
            return;
        }
        //get paired connid
        let mut paired_connid: Vec<(u16, u16)> = vec![];
        for i in (0..(conn_ids.len() / 2 * 2)).step_by(2) {
            if conn_ids[i] == conn_ids[i + 1] - 1 {
                paired_connid.push((conn_ids[i], conn_ids[i + 1]))
            }
        }
        for (connid1, connid2) in paired_connid {
            let mut packets1: Vec<&UdpPeerPacket> = vec![];
            let mut packets2: Vec<&UdpPeerPacket> = vec![];
            for &x in utp_packet.iter() {
                if let UdpPeerPacketEnum::Utp(e) = &x.data {
                    if e.connid == connid1 && e.type_ver == 0x01 {
                        packets1.push(x);
                    } else if e.connid == connid2 && e.type_ver == 0x01 {
                        packets2.push(x);
                    }
                }
            }
            packets1.sort_by(|x, y| {
                if let UdpPeerPacketEnum::Utp(e1) = &x.data {
                    if let UdpPeerPacketEnum::Utp(e2) = &y.data {
                        return e1.seq.cmp(&e2.seq);
                    }
                }
                return Ordering::Equal;
            });
            packets1.dedup_by(|x, y| {
                if let UdpPeerPacketEnum::Utp(e1) = &x.data {
                    if let UdpPeerPacketEnum::Utp(e2) = &y.data {
                        return e1.seq.eq(&e2.seq);
                    }
                }
                return false;
            });
            packets2.sort_by(|x, y| {
                if let UdpPeerPacketEnum::Utp(e1) = &x.data {
                    if let UdpPeerPacketEnum::Utp(e2) = &y.data {
                        return e1.seq.cmp(&e2.seq);
                    }
                }
                return Ordering::Equal;
            });
            packets2.dedup_by(|x, y| {
                if let UdpPeerPacketEnum::Utp(e1) = &x.data {
                    if let UdpPeerPacketEnum::Utp(e2) = &y.data {
                        return e1.seq.eq(&e2.seq);
                    }
                }
                return false;
            });

            if let Some(e) = self.utp_binary_flow.get_mut(&connid1) {
                for p in packets1 {
                    if let UdpPeerPacketEnum::Utp(d) = &p.data {
                        e.0.extend_from_slice(d.payload.as_slice());
                    }
                }
                for p in packets2 {
                    if let UdpPeerPacketEnum::Utp(d) = &p.data {
                        e.1.extend_from_slice(d.payload.as_slice());
                    }
                }
            } else {
                let mut e0 = BytesMut::with_capacity(64);
                let mut e1 = BytesMut::with_capacity(64);
                for p in packets1 {
                    if let UdpPeerPacketEnum::Utp(d) = &p.data {
                        e0.extend_from_slice(d.payload.as_slice());
                    }
                }
                for p in packets2 {
                    if let UdpPeerPacketEnum::Utp(d) = &p.data {
                        e1.extend_from_slice(d.payload.as_slice());
                    }
                }
                self.utp_binary_flow.insert(connid1, (e0, e1));
            }
        }
        self.packets.clear();
    }
}
