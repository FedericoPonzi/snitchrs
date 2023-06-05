#![no_std]
#![no_main]
use aya_bpf::bindings::{TC_ACT_PIPE, TC_ACT_SHOT};
use aya_bpf::helpers::{bpf_get_current_pid_tgid, bpf_probe_read_kernel, bpf_probe_read_user};
use aya_bpf::macros::{classifier, map};
use aya_bpf::maps::PerfEventArray;
use aya_bpf::programs::{ProbeContext, TcContext};
use aya_log_ebpf::info;
mod bindings_linux_in;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
};

use snitchrs_common::{SnitchrsDirection, SnitchrsEvent};

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[map]
static mut EVENT_QUEUE: PerfEventArray<SnitchrsEvent> = PerfEventArray::with_max_entries(0, 0);

#[classifier(name = "snitchrs_ingress")]
pub fn snitchrs_ingress(ctx: TcContext) -> i32 {
    match try_snitchrs(ctx, SnitchrsDirection::Ingress) {
        Ok(_) => TC_ACT_PIPE,
        Err(_) => TC_ACT_SHOT,
    }
}

#[classifier(name = "snitchrs")]
pub fn snitchrs(ctx: TcContext) -> i32 {
    match try_snitchrs(ctx, SnitchrsDirection::Egress) {
        Ok(_) => TC_ACT_PIPE,
        Err(_) => TC_ACT_SHOT,
    }
}

#[inline]
fn try_snitchrs(ctx: TcContext, ingress: SnitchrsDirection) -> Result<(), ()> {
    let ethhdr: EthHdr = ctx.load(0).map_err(|_| ())?;
    match ethhdr.ether_type {
        EtherType::Ipv4 => {}
        _ => return Ok(()),
    }
    let ipv4hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
    if ipv4hdr.proto != IpProto::Tcp {
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

    unsafe {
        EVENT_QUEUE.output(&ctx, ev, 0);
    }

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

use crate::bindings_linux_in::{__be32, __kernel_sa_family_t, in_addr, sockaddr_in};
use aya_bpf::macros::uprobe;

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

#[uprobe(name = "snitchrs_connect")]
pub fn uprobe_connect_tcp(ctx: ProbeContext) -> u32 {
    match try_uprobe_connect_tcp(ctx) {
        Ok(ret) => ret,
        Err(ret) => match ret.try_into() {
            Ok(rt) => rt,
            Err(_) => 1,
        },
    }
}

#[inline]
fn try_uprobe_connect_tcp(ctx: ProbeContext) -> Result<u32, i64> {
    //  int connect(int sockfd, const struct sockaddr *addr,
    //                    socklen_t addrlen);
    let sockaddr: *mut sockaddr_in = ctx.arg(1).ok_or(1i64)?;
    let family = unsafe {
        bpf_probe_read_user(&(*sockaddr).sin_family as *const __kernel_sa_family_t)
            .map_err(|e| e)?
    };
    let addr: in_addr =
        unsafe { bpf_probe_read_user(&(*sockaddr).sin_addr as *const in_addr).map_err(|e| e)? };
    let port = unsafe {
        bpf_probe_read_user(&(*sockaddr).sin_port as *const crate::bindings_linux_in::__be16)
            .map_err(|e| e)?
    };

    let pid = bpf_get_current_pid_tgid() as u32;

    let s_addr = unsafe { bpf_probe_read_user(&(addr).s_addr as *const __be32).map_err(|e| e)? };
    let ip = u32::from_be(s_addr);
    if family == AF_INET {
        let event = &SnitchrsEvent::new_connect_func(ip, port, pid);
        unsafe {
            EVENT_QUEUE.output(&ctx, event, 0);
        }
    }
    Ok(0)
}
