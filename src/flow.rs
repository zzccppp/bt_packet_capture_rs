use std::collections::HashMap;

use crate::parser::{InetAddr, PacketQuadruple, SimpleParsedPacket};

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
    packets: Vec<SimpleParsedPacket>,
    info: PacketQuadruple,
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
