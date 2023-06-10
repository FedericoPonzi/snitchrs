use crate::maps::EVENT_QUEUE;
use aya_bpf::bindings::{TC_ACT_PIPE, TC_ACT_SHOT};
use aya_bpf::macros::classifier;
use aya_bpf::programs::TcContext;
use aya_log_ebpf::debug;
use snitchrs_common::{SnitchrsDirection, SnitchrsEvent};

use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
};

#[classifier(name = "snitchrs_classifier_ingress")]
pub fn snitchrs_ingress(ctx: TcContext) -> i32 {
    match try_snitchrs(ctx, SnitchrsDirection::Ingress) {
        Ok(_) => TC_ACT_PIPE,
        Err(_) => TC_ACT_SHOT,
    }
}

#[classifier(name = "snitchrs_classifier_egress")]
pub fn snitchrs(ctx: TcContext) -> i32 {
    match try_snitchrs(ctx, SnitchrsDirection::Egress) {
        Ok(_) => TC_ACT_PIPE,
        Err(_) => TC_ACT_SHOT,
    }
}

#[inline]
fn try_snitchrs(ctx: TcContext, ingress: SnitchrsDirection) -> Result<(), ()> {
    let ethhdr: EthHdr = ctx.load(0).map_err(|_| ())?;
    if !matches!(ethhdr.ether_type, EtherType::Ipv4) {
        return Ok(());
    }

    let ipv4hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
    if !matches!(ipv4hdr.proto, IpProto::Tcp) {
        return Ok(());
    }
    // only works with Ipv4 and TCP for now...

    let destination_ip = u32::from_be(ipv4hdr.dst_addr);
    let source_ip = u32::from_be(ipv4hdr.src_addr);
    let transport_hdr_offset = EthHdr::LEN + Ipv4Hdr::LEN;

    let tcp_hdr: TcpHdr = ctx.load(transport_hdr_offset).map_err(|_| ())?;
    let destination_port = u16::from_be(tcp_hdr.dest);
    let source_port = u16::from_be(tcp_hdr.source);
    /*
    The TCP payload size is calculated by taking the "Total Length" from the IP
    header (ip.len) and then substract the "IP header length" (ip.hdr_len) and the
    "TCP header length" (tcp.hdr_len).
    */
    let payload_size = ipv4hdr.tot_len - Ipv4Hdr::LEN as u16 + TcpHdr::LEN as u16;
    let ev = &get_event(
        &ctx,
        ingress,
        is_initial_packet(&tcp_hdr),
        is_fin_packet(&tcp_hdr),
        source_ip,
        source_port,
        destination_ip,
        destination_port,
        payload_size,
    );

    EVENT_QUEUE.output(&ctx, ev, 0);

    //info!(&ctx, "DEST {:ipv4}, ACTION {}", destination, action);
    Ok(())
}

#[inline]
fn get_event(
    _ctx: &TcContext,
    direction: SnitchrsDirection,
    is_initial_packet: bool,
    is_fin_packet: bool,
    source_ip: u32,
    source_port: u16,
    destination_ip: u32,
    destination_port: u16,
    payload_size: u16,
) -> SnitchrsEvent {
    /*info!(
    ctx,
    "DEST {:ipv4}, source {:ipv4}", destination_ip, source_ip
    );*/
    let (remote_ip, remote_port, local_port) = if direction == SnitchrsDirection::Ingress {
        (source_ip, source_port, destination_port)
    } else {
        (destination_ip, destination_port, source_port)
    };
    if is_initial_packet {
        SnitchrsEvent::new_connect(remote_ip, remote_port, local_port, direction)
    } else if is_fin_packet {
        SnitchrsEvent::new_disconnect(remote_ip, remote_port, local_port, direction)
    } else {
        SnitchrsEvent::new_traffic(remote_ip, remote_port, local_port, payload_size, direction)
    }
}

#[inline]
fn is_initial_packet(packet: &TcpHdr) -> bool {
    packet.syn() == 1
}

#[inline]
fn is_fin_packet(packet: &TcpHdr) -> bool {
    packet.fin() == 1
}
