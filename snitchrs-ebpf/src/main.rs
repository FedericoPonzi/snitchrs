#![no_std]
#![no_main]

use aya_bpf::bindings::{TC_ACT_PIPE, TC_ACT_SHOT};
use aya_bpf::macros::{classifier, map};
use aya_bpf::maps::{HashMap, PerfEventArray, Queue};
use aya_bpf::programs::TcContext;
use aya_bpf::{bindings::xdp_action, macros::xdp, programs::XdpContext, BpfContext};
use aya_log_ebpf::info;
use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};
use snitchrs_common::SnitchrsEvent;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[map]
static mut EVENT_QUEUE: PerfEventArray<SnitchrsEvent> = PerfEventArray::with_max_entries(0, 0);

#[classifier(name = "snitchrs_ingress")]
pub fn snitchrs_ingress(ctx: TcContext) -> i32 {
    match try_snitchrs(ctx, true) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_SHOT,
    }
}

#[classifier(name = "snitchrs")]
pub fn snitchrs(ctx: TcContext) -> i32 {
    match try_snitchrs(ctx, false) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_SHOT,
    }
}

fn try_snitchrs(ctx: TcContext, ingress: bool) -> Result<i32, ()> {
    let ethhdr: EthHdr = ctx.load(0).map_err(|_| ())?;
    match ethhdr.ether_type {
        EtherType::Ipv4 => {}
        _ => return Ok(TC_ACT_PIPE),
    }
    let ipv4hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
    if ipv4hdr.proto != IpProto::Tcp {
        return Ok(TC_ACT_PIPE);
    }
    // only works with Ipv4 and TCP for now...

    let destination_ip = u32::from_be(ipv4hdr.dst_addr);
    let source_ip = u32::from_be(ipv4hdr.src_addr);
    let transport_hdr_offset = EthHdr::LEN + Ipv4Hdr::LEN;

    let tcp_hdr: TcpHdr = ctx.load(transport_hdr_offset).map_err(|_| ())?;
    let destination_port = tcp_hdr.dest;
    let source_port = tcp_hdr.source;
    /*
    The TCP payload size is calculated by taking the "Total Length" from the IP
    header (ip.len) and then substract the "IP header length" (ip.hdr_len) and the
    "TCP header length" (tcp.hdr_len).
    */
    let payload_size = ipv4hdr.tot_len - 20;

    unsafe {
        EVENT_QUEUE.output(
            &ctx,
            &get_event(
                &ctx,
                ingress,
                is_initial_packet(&tcp_hdr),
                source_ip,
                u16::from_be(source_port),
                destination_ip,
                u16::from_be(destination_port),
                payload_size,
            ),
            0,
        );
    }

    //info!(&ctx, "DEST {:ipv4}, ACTION {}", destination, action);
    Ok(TC_ACT_PIPE)
}

#[inline]
fn get_event(
    ctx: &TcContext,
    ingress: bool,
    is_initial_packet: bool,
    source_ip: u32,
    source_port: u16,
    destination_ip: u32,
    destination_port: u16,
    payload_size: u16,
) -> SnitchrsEvent {
    if ingress {
        SnitchrsEvent::new_ingress_traffic(source_ip, source_port, destination_port, payload_size)
    } else {
        if is_initial_packet {
            /*info!(
                ctx,
                "DEST {:ipv4}, source {:ipv4}", destination_ip, source_ip
            );*/

            SnitchrsEvent::new_connect(destination_ip, destination_port, source_port)
        } else {
            SnitchrsEvent::new_egress_traffic(
                destination_ip,
                source_port,
                destination_port,
                payload_size,
            )
        }
    }
}

#[inline]
fn is_initial_packet(packet: &TcpHdr) -> bool {
    let syn_flag = packet.syn() == 1;
    let ack_flag = packet.ack() == 1;

    syn_flag && !ack_flag
}
