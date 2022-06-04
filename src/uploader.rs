use serde::Serialize;
use tracing::info;

use crate::{
    flow::{BitTorrentMessage, BittorrentFlow},
    parser::BittorrentFlowInfCache,
};

/*
Post form
static class CollectConnInfForm {
    public String src_ip;
    public String dst_ip;
    public int src_port;
    public int dst_port;
    public String info_hash;
    public String protocol;
    public long last_act_time;
    public String client_name1;
    public String client_name2;
}
*/
#[derive(Debug, Clone, Serialize)]
struct CollectConnInfForm {
    src_ip: String,
    dst_ip: String,
    src_port: u16,
    dst_port: u16,
    info_hash: String,
    protocol: String,
    last_act_time: u64,
    client_name1: String,
    client_name2: String,
}
pub fn send_basic_inf(cache: &BittorrentFlowInfCache, flow: &BittorrentFlow, protocol: &str) {
    if let Some(flag) = cache.is_info_reverse(flow) {
        let add_inf = cache.get_info(flow).unwrap();
        let info_hash = base64::encode(&add_inf.info_hash);
        let form = if flag {
            // reverse
            CollectConnInfForm {
                src_ip: flow.info1.dst_ip.to_string(),
                dst_ip: flow.info1.src_ip.to_string(),
                src_port: flow.info1.dst_port,
                dst_port: flow.info1.src_port,
                info_hash,
                protocol: protocol.to_string(),
                last_act_time: flow.end_timeval.to_timestamp(),
                client_name1: add_inf.peer_client1.clone(),
                client_name2: add_inf.peer_client2.clone(),
            }
        } else {
            CollectConnInfForm {
                src_ip: flow.info1.src_ip.to_string(),
                dst_ip: flow.info1.dst_ip.to_string(),
                src_port: flow.info1.src_port,
                dst_port: flow.info1.dst_port,
                info_hash,
                protocol: protocol.to_string(),
                last_act_time: flow.end_timeval.to_timestamp(),
                client_name1: add_inf.peer_client1.clone(),
                client_name2: add_inf.peer_client2.clone(),
            }
        };
        tokio::spawn(async move {
            let client = reqwest::Client::new();
            let res = client
                .post("http://localhost:9900/public/collectConnInf")
                .json(&form)
                .send()
                .await
                .unwrap();
            info!("Response: {:?}", res);
        });
    }
}

#[derive(Debug, Clone, Serialize)]
struct UpdateConnInfForm {
    src_ip: String,
    dst_ip: String,
    src_port: u16,
    dst_port: u16,
    info_hash: String,
    last_act_time: u64,
    message_count1: usize,
    message_count2: usize,
    transfer_bytes1: usize,
    transfer_bytes2: usize,
}

pub fn send_message_count_and_transfer_bytes(
    cache: &BittorrentFlowInfCache,
    flow: &BittorrentFlow,
) {
    if let Some(flag) = cache.is_info_reverse(flow) {
        let add_inf = cache.get_info(flow).unwrap();
        let info_hash = base64::encode(&add_inf.info_hash);
        let count = flow.get_message_counts();
        let bytes = flow.get_piece_bytes();
        let form = if flag {
            // reverse
            UpdateConnInfForm {
                src_ip: flow.info1.dst_ip.to_string(),
                dst_ip: flow.info1.src_ip.to_string(),
                src_port: flow.info1.dst_port,
                dst_port: flow.info1.src_port,
                info_hash,
                last_act_time: flow.end_timeval.to_timestamp(),
                message_count1: count.1,
                message_count2: count.0,
                transfer_bytes1: bytes.1,
                transfer_bytes2: bytes.0,
            }
        } else {
            UpdateConnInfForm {
                src_ip: flow.info1.src_ip.to_string(),
                dst_ip: flow.info1.dst_ip.to_string(),
                src_port: flow.info1.src_port,
                dst_port: flow.info1.dst_port,
                info_hash,
                last_act_time: flow.end_timeval.to_timestamp(),
                message_count1: count.0,
                message_count2: count.1,
                transfer_bytes1: bytes.0,
                transfer_bytes2: bytes.1,
            }
        };
        tokio::spawn(async move {
            let client = reqwest::Client::new();
            let res = client
                .post("http://localhost:9900/public/updateConnInf")
                .json(&form)
                .send()
                .await
                .unwrap();
            info!("Response: {:?}", res);
        });
    }
}

#[derive(Debug, Clone, Serialize)]
struct FilePieceForm {
    info_hash: String,
    piece_index: u32,
    begin_piece_offset: u32,
    file_piece: String,
}

pub fn send_file_piece(cache: &mut BittorrentFlowInfCache, flow: &BittorrentFlow) {
    if let Some(inf) = cache.get_info(flow) {
        let info_hash = base64::encode(&inf.info_hash);
        if let BitTorrentMessage::Piece {
            piece_index: idx,
            begin_piece_offset: off,
            data,
        } = flow.get_a_piece_message()
        {
            if cache.get_file_piece_sent(&info_hash) > 5 {
                return;
            }
            cache.file_piece_sent_inc(&info_hash);
            let form = FilePieceForm {
                info_hash,
                piece_index: *idx,
                begin_piece_offset: *off,
                file_piece: base64::encode(&data),
            };
            tokio::spawn(async move {
                let client = reqwest::Client::new();
                let res = client
                    .post("http://localhost:9900/public/uploadFilePiece")
                    .json(&form)
                    .send()
                    .await
                    .unwrap();
                info!("Response: {:?}", res);
            });
        }
    }
}
