use crate::parser::SimpleDumpCodec;
use futures::StreamExt;
use inquire::{Select, Text};
use parser::start_new_stream;
use pcap::stream::PacketCodec;
use pcap::{Capture, Device};
use tracing::info;

pub mod parser;

fn main() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .unwrap();

    let device_list = Device::list().unwrap();

    let mut device_list_name: Vec<String> =
        device_list.iter().map(|dev| dev.name.clone()).collect();
    device_list_name.push("Read Pcap File".to_string());

    // let sel = Select::new("Select a device", device_list_name.clone())
    //     .prompt()
    //     .unwrap();

    // let index = device_list_name.iter().position(|s| *s == sel).unwrap();
    let index = 0;

    //start the log
    tracing_subscriber::fmt::init();

    if index == device_list_name.len() - 1 {
        // select the file option
        let filepath = Text::new("Enter pcap file path").prompt().unwrap();
        info!("use the file {}", filepath);
        rt.block_on(async {
            let mut cap = Capture::from_file(filepath).unwrap();
            while let Ok(pcap) = cap.next() {
                let mut codec = SimpleDumpCodec {};
                let s = codec.decode(pcap).unwrap();
                // println!("{}", s);
            }
        });
    } else {
        let stream = rt.block_on(start_new_stream(device_list[index].clone()));

        rt.block_on(stream.for_each(move |s| {
            if let Ok(s) = s {
                // println!("{:?}", s);
            }
            futures::future::ready(())
        }));
    }
}
