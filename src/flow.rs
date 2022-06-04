use std::{cmp::Ordering, collections::HashMap, io::Cursor};

use aho_corasick::AhoCorasick;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use tracing::{info, instrument};

use crate::parser::{InetAddr, PacketQuadruple, SimpleParsedPacket, TimeVal};

pub const BITTORRENT_HANDSHAKE_HEADER: [u8; 20] = [
    0x13, 0x42, 0x69, 0x74, 0x54, 0x6f, 0x72, 0x72, 0x65, 0x6e, 0x74, 0x20, 0x70, 0x72, 0x6f, 0x74,
    0x6f, 0x63, 0x6f, 0x6c,
];

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
        info_hash: Bytes,
        peer_id: Bytes,
    },
    Choke,         //no payload
    Unchoke,       //no payload
    Interested,    //no payload
    NotInterested, //no payload
    Have {
        idx: u32,
    },
    Bitfield {
        bitfield: Bytes,
    },
    Request {
        piece_index: u32,
        begin_piece_offset: u32,
        piece_length: u32,
    },
    Piece {
        piece_index: u32,
        begin_piece_offset: u32,
        data: Bytes,
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
        data: Bytes,
    },
}

#[derive(Debug, Clone)]
pub struct BittorrentFlow {
    pub messages1: Vec<BitTorrentMessage>,
    pub messages2: Vec<BitTorrentMessage>,
    pub info_hash: Option<Bytes>, // 如果没有，则证明没有找到握手信息
    pub info1: PacketQuadruple,
    pub start_timeval: TimeVal,
    pub end_timeval: TimeVal,
}

impl BittorrentFlow {
    pub fn get_a_piece_message(&self) -> &BitTorrentMessage {
        let fd = self.messages1.iter().find(|m| {
            if let BitTorrentMessage::Piece { .. } = m {
                true
            } else {
                false
            }
        });
        if let Some(fd) = fd {
            return fd;
        }
        let fd = self.messages2.iter().find(|m| {
            if let BitTorrentMessage::Piece { .. } = m {
                true
            } else {
                false
            }
        });
        return fd.unwrap();
    }
    pub fn get_message_counts(&self) -> (usize, usize) {
        return (self.messages1.len(), self.messages2.len());
    }

    pub fn get_piece_bytes(&self) -> (usize, usize) {
        let mut sum1 = 0;
        let mut sum2 = 0;
        for m in self.messages1.iter() {
            if let BitTorrentMessage::Piece {
                piece_index: _idx,
                begin_piece_offset: _off,
                data: d,
            } = m
            {
                sum1 += d.len();
            }
        }
        for m in self.messages2.iter() {
            if let BitTorrentMessage::Piece {
                piece_index: _idx,
                begin_piece_offset: _off,
                data: d,
            } = m
            {
                sum2 += d.len();
            }
        }
        (sum1, sum2)
    }

    pub fn get_all_piece_length(&self) -> usize {
        let mut sum = 0;
        for m in self.messages1.iter() {
            if let BitTorrentMessage::Piece {
                piece_index: _idx,
                begin_piece_offset: _off,
                data: d,
            } = m
            {
                sum += d.len();
            }
        }
        for m in self.messages2.iter() {
            if let BitTorrentMessage::Piece {
                piece_index: _idx,
                begin_piece_offset: _off,
                data: d,
            } = m
            {
                sum += d.len();
            }
        }
        sum
    }
}

#[derive(Debug, Clone)]
pub struct TcpPeerFlow {
    pub info1: PacketQuadruple,
    pub info2: PacketQuadruple,
    pub binary_buf1: BytesMut,
    pub binary_buf2: BytesMut,
    pub start_timeval: TimeVal,
    pub end_timeval: TimeVal,
}

impl TcpPeerFlow {
    pub fn new(flow: Flow) -> Self {
        let start_timeval = flow.packets[0].timeval;
        let end_timeval = flow.packets[flow.packets.len() - 1].timeval;
        let mut packets1: Vec<&SimpleParsedPacket> = flow
            .packets
            .iter()
            .filter(|x| {
                x.info.get_src_dst_tuple() == flow.info.get_src_dst_tuple() && x.payload.len() != 0
            })
            .collect();
        let mut packets2: Vec<&SimpleParsedPacket> = flow
            .packets
            .iter()
            .filter(|x| {
                x.info.get_src_dst_tuple() == flow.info.get_dst_src_tuple() && x.payload.len() != 0
            })
            .collect();

        packets1.sort_by(|x, y| x.info.get_tcp_seq().cmp(&y.info.get_tcp_seq()));
        packets1.dedup_by(|x, y| x.info.get_tcp_seq() == y.info.get_tcp_seq());
        packets2.sort_by(|x, y| x.info.get_tcp_seq().cmp(&y.info.get_tcp_seq()));
        packets2.dedup_by(|x, y| x.info.get_tcp_seq() == y.info.get_tcp_seq());

        // reassemble into binary flow
        let mut binary_buf1 = BytesMut::with_capacity(64);
        let mut binary_buf2 = BytesMut::with_capacity(64);
        for p in packets1 {
            binary_buf1.extend_from_slice(p.payload.as_slice());
        }
        for p in packets2 {
            binary_buf2.extend_from_slice(p.payload.as_slice());
        }

        Self {
            info1: flow.info.clone(),
            info2: flow.info.get_reverse_self(),
            binary_buf1,
            binary_buf2,
            start_timeval,
            end_timeval,
        }
    }

    pub fn add_packets(&mut self, flow: Flow) {
        self.end_timeval = flow.packets[flow.packets.len() - 1].timeval;
        let mut packets1: Vec<&SimpleParsedPacket> = flow
            .packets
            .iter()
            .filter(|x| {
                x.info.get_src_dst_tuple() == self.info1.get_src_dst_tuple() && x.payload.len() != 0
            })
            .collect();
        let mut packets2: Vec<&SimpleParsedPacket> = flow
            .packets
            .iter()
            .filter(|x| {
                x.info.get_src_dst_tuple() == self.info2.get_src_dst_tuple() && x.payload.len() != 0
            })
            .collect();

        packets1.sort_by(|x, y| x.info.get_tcp_seq().cmp(&y.info.get_tcp_seq()));
        packets1.dedup_by(|x, y| x.info.get_tcp_seq() == y.info.get_tcp_seq());
        packets2.sort_by(|x, y| x.info.get_tcp_seq().cmp(&y.info.get_tcp_seq()));
        packets2.dedup_by(|x, y| x.info.get_tcp_seq() == y.info.get_tcp_seq());

        // reassemble into binary flow
        for p in packets1 {
            self.binary_buf1.extend_from_slice(p.payload.as_slice());
        }
        for p in packets2 {
            self.binary_buf2.extend_from_slice(p.payload.as_slice());
        }
    }

    pub fn get_result_from_buf(&mut self, ac: &AhoCorasick) -> BittorrentFlow {
        let message1 = parse_bt_stream(&mut self.binary_buf1, ac);
        let message2 = parse_bt_stream(&mut self.binary_buf2, ac);

        let mut ifhs = None;

        let re0 = message1.iter().find(|x| {
            if let BitTorrentMessage::HandShake { .. } = x {
                true
            } else {
                false
            }
        });
        if let Some(x) = re0 {
            if let BitTorrentMessage::HandShake {
                info_hash,
                peer_id: _,
            } = x
            {
                ifhs = Some(info_hash.clone());
            }
        } else {
            let re1 = message2.iter().find(|x| {
                if let BitTorrentMessage::HandShake { .. } = x {
                    true
                } else {
                    false
                }
            });
            if let Some(x) = re1 {
                if let BitTorrentMessage::HandShake {
                    info_hash,
                    peer_id: _,
                } = x
                {
                    ifhs = Some(info_hash.clone());
                }
            }
        }

        BittorrentFlow {
            messages1: message1,
            messages2: message2,
            info_hash: ifhs,
            info1: self.info1.clone(),
            start_timeval: self.start_timeval,
            end_timeval: self.end_timeval,
        }
    }
}

#[derive(Debug, Clone)]
pub struct UdpPeerFlow {
    pub packets: Vec<UdpPeerPacket>,
    pub info: PacketQuadruple,
    pub utp_binary_flow: (BytesMut, BytesMut),
    pub start_timeval: TimeVal,
    pub end_timeval: TimeVal,
}

fn parse_bt_stream(b0: &mut BytesMut, ac: &AhoCorasick) -> Vec<BitTorrentMessage> {
    let mut msg1 = Vec::new();
    loop {
        if b0.len() < 5 {
            break;
        }
        if b0.starts_with(&BITTORRENT_HANDSHAKE_HEADER) {
            if b0.len() < 68 {
                break;
            }
            let mut packet = b0.split_to(68);
            packet.advance(28);
            let info_hash = packet.split_to(20).freeze();
            let peer_id = packet.freeze();
            msg1.push(BitTorrentMessage::HandShake { info_hash, peer_id });
        } else {
            let msg_len = b0.get(0..4).unwrap().get_u32();
            let msg_type = b0[4];
            // 这里检测信息长度，现在的bt实现piece都在16kb，所以最大长度为0x4009,根据规范，消息类型的编码至多为0x17
            if msg_len < 0x5000 && msg_len != 0 && msg_type < 0x20 {
                if b0.len() >= msg_len as usize + 4 {
                    // real message
                    let mut packet = b0.split_to(msg_len as usize + 4);
                    packet.advance(5);
                    let mut payload = packet.freeze();
                    match msg_type {
                        0x00 => {
                            //Choke
                            msg1.push(BitTorrentMessage::Choke);
                        }
                        0x01 => {
                            //UnChoke
                            msg1.push(BitTorrentMessage::Unchoke);
                        }
                        0x02 => {
                            //Interested
                            msg1.push(BitTorrentMessage::Interested);
                        }
                        0x03 => {
                            //NotInterested
                            msg1.push(BitTorrentMessage::NotInterested);
                        }
                        0x04 => {
                            //Have
                            if payload.len() == 4 {
                                let idx = payload.get_u32();
                                msg1.push(BitTorrentMessage::Have { idx });
                            }
                        }
                        0x05 => {
                            //Bitfield
                            if payload.len() > 0 {
                                msg1.push(BitTorrentMessage::Bitfield { bitfield: payload })
                            }
                        }
                        0x06 => {
                            //Request
                            if payload.len() == 12 {
                                let piece_index = payload.get_u32();
                                let begin_piece_offset = payload.get_u32();
                                let piece_length = payload.get_u32();
                                msg1.push(BitTorrentMessage::Request {
                                    piece_index,
                                    begin_piece_offset,
                                    piece_length,
                                });
                            }
                        }
                        0x07 => {
                            //Piece
                            if payload.len() > 8 {
                                let piece_index = payload.get_u32();
                                let begin_piece_offset = payload.get_u32();
                                msg1.push(BitTorrentMessage::Piece {
                                    piece_index,
                                    begin_piece_offset,
                                    data: payload,
                                });
                            }
                        }
                        0x08 => {
                            //Cancel
                            if payload.len() == 12 {
                                let piece_index = payload.get_u32();
                                let begin_piece_offset = payload.get_u32();
                                let piece_length = payload.get_u32();
                                msg1.push(BitTorrentMessage::Cancel {
                                    piece_index,
                                    begin_piece_offset,
                                    piece_length,
                                });
                            }
                        }
                        0x09 => {
                            msg1.push(BitTorrentMessage::Port);
                        }
                        0x14 => msg1.push(BitTorrentMessage::Extended { data: payload }),
                        _ => {}
                    }
                } else {
                    break;
                }
            } else {
                // 进入丢弃模式
                // 利用AC算法，匹配可能的header
                let mut flag = false;
                for mat in ac.find_iter(&b0) {
                    if mat.start() != 0 {
                        flag = true;
                        b0.advance(mat.start());
                        break;
                    }
                }
                if !flag {
                    //not fond;
                    //remain 3 characters for pattern handshake
                    b0.advance(b0.len() - 3);
                    break;
                }
            }
        }
    }
    return msg1;
}

impl UdpPeerFlow {
    pub fn from_flow(flow: &Flow) -> Self {
        let mut peer_packets = vec![];
        for p in flow.packets.iter() {
            peer_packets.push(UdpPeerPacket::from_simple_packet(p));
        }
        peer_packets.sort_by(|x, y| x.timeval.cmp(&y.timeval));
        let start_timeval = if peer_packets.len() == 0 {
            TimeVal {
                tv_sec: i64::MAX,
                tv_usec: i64::MAX,
            }
        } else {
            peer_packets[0].timeval.clone()
        };
        let end_timeval = if peer_packets.len() == 0 {
            TimeVal {
                tv_sec: 0,
                tv_usec: 0,
            }
        } else {
            peer_packets[peer_packets.len() - 1].timeval.clone()
        };
        Self {
            packets: peer_packets,
            info: flow.info.clone(),
            utp_binary_flow: (BytesMut::with_capacity(64), BytesMut::with_capacity(64)),
            start_timeval,
            end_timeval,
        }
    }

    pub fn get_result_from_buf(&mut self, ac: &AhoCorasick) -> BittorrentFlow {
        let (b0, b1) = &mut self.utp_binary_flow;
        let msg0 = parse_bt_stream(b0, ac);
        let msg1 = parse_bt_stream(b1, ac);
        let mut ifhs = None;

        let re0 = msg0.iter().find(|x| {
            if let BitTorrentMessage::HandShake { .. } = x {
                true
            } else {
                false
            }
        });
        if let Some(x) = re0 {
            if let BitTorrentMessage::HandShake {
                info_hash,
                peer_id: _,
            } = x
            {
                ifhs = Some(info_hash.clone());
            }
        } else {
            let re1 = msg1.iter().find(|x| {
                if let BitTorrentMessage::HandShake { .. } = x {
                    true
                } else {
                    false
                }
            });
            if let Some(x) = re1 {
                if let BitTorrentMessage::HandShake {
                    info_hash,
                    peer_id: _,
                } = x
                {
                    ifhs = Some(info_hash.clone());
                }
            }
        }

        let bt_flow = BittorrentFlow {
            messages1: msg0,
            messages2: msg1,
            info1: self.info.clone(),
            info_hash: ifhs,
            start_timeval: self.start_timeval.clone(),
            end_timeval: self.end_timeval.clone(),
        };

        bt_flow
    }

    pub fn add_packets(&mut self, flow: &Flow) {
        for p in flow.packets.iter() {
            let re = UdpPeerPacket::from_simple_packet(p);
            // println!("{:?}", re);
            self.packets.push(re);
        }
        self.packets.sort_by(|x, y| x.timeval.cmp(&y.timeval));
        if self.packets.len() != 0 {
            if self.packets[self.packets.len() - 1].timeval > self.end_timeval {
                self.end_timeval = self.packets[self.packets.len() - 1].timeval.clone();
            }
            if self.packets[0].timeval < self.start_timeval {
                self.start_timeval = self.packets[0].timeval.clone();
            }
        }
    }

    pub fn filter_utp_to_buf(&mut self) {
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

        let mut packets1: Vec<&UdpPeerPacket> = vec![];
        let mut packets2: Vec<&UdpPeerPacket> = vec![];
        for &x in utp_packet.iter() {
            if let UdpPeerPacketEnum::Utp(e) = &x.data {
                if x.info.get_src_dst_tuple() == self.info.get_src_dst_tuple() && e.type_ver == 0x01
                {
                    packets1.push(x);
                } else if x.info.get_src_dst_tuple() == self.info.get_dst_src_tuple()
                    && e.type_ver == 0x01
                {
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

        if packets1.is_empty() && packets2.is_empty() {
            return;
        }

        for p in packets1 {
            if let UdpPeerPacketEnum::Utp(d) = &p.data {
                self.utp_binary_flow
                    .0
                    .extend_from_slice(d.payload.as_slice());
            }
        }
        for p in packets2 {
            if let UdpPeerPacketEnum::Utp(d) = &p.data {
                self.utp_binary_flow
                    .1
                    .extend_from_slice(d.payload.as_slice());
            }
        }
        self.packets.clear();
    }
}

#[cfg(test)]
pub mod tests {
    use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
    use bytes::{Buf, Bytes, BytesMut};

    #[test]
    fn test_ac_automata() {
        let patterns = [b"\x00\x00".to_vec(), b"\x13\x42\x69\x74".to_vec()];
        let ac = AhoCorasick::new(&patterns);
        let mut string = BytesMut::from(
            &b"\x01\x00\x00\x00\x99\x14\x00\x64\x31\x32\x3a\x63\x6f\x6d\x70\x6c\x65\x13\x42\x69\x74"[..],
        );
        println!("{:?}", string);
        let mut matches = vec![];
        for mat in ac.find_overlapping_iter(&string.to_vec()) {
            matches.push((mat.pattern(), mat.start(), mat.end()));
        }
        println!("{:?}", matches);
        string.advance(string.len() - 1);
        println!("{:?}", string);
    }
}
