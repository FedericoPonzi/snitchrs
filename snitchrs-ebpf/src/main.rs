#![no_std]
#![feature(strict_provenance)]
#![no_main]

use aya_bpf::bindings::{sa_family_t, sockaddr};
use aya_bpf::bindings::{TC_ACT_PIPE, TC_ACT_SHOT};
use aya_bpf::helpers::{
    bpf_get_current_pid_tgid, bpf_probe_read, bpf_probe_read_kernel, bpf_probe_read_user,
};
use aya_bpf::macros::{classifier, map};
use aya_bpf::maps::{HashMap, PerfEventArray};
use aya_bpf::programs::{ProbeContext, TcContext};
use aya_log_ebpf::{debug, error, info};
use core::cell::UnsafeCell;
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
static EVENT_QUEUE: PerfEventArray<SnitchrsEvent> = PerfEventArray::with_max_entries(0, 0);

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
use aya_bpf::macros::{kprobe, kretprobe};
use aya_bpf::PtRegs;

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

#[kprobe(name = "snitchrs_connect")]
pub fn uprobe_connect_tcp(ctx: ProbeContext) -> u32 {
    match try_kprobe_connect_tcp(&ctx) {
        Ok(ret) => ret,
        Err(err) => match err.try_into() {
            Ok(rt) => rt,
            Err(_) => 1,
        },
    }
}

fn try_kprobe_connect_tcp(ctx: &ProbeContext) -> Result<u32, i64> {
    //  int connect(int sockfd, const struct sockaddr *addr,
    //                    socklen_t addrlen);
    if ctx.regs.is_null() {
        return Ok(0);
    }
    let regs = PtRegs::new(ctx.arg(0).ok_or(1u32)?);
    let sockaddr: *const sockaddr = regs.arg(1).ok_or(1i64)?;
    let (ip, port) = parse_sockaddr(sockaddr)?.ok_or(1i64)?;
    let pid = bpf_get_current_pid_tgid() as u32;
    let event = &SnitchrsEvent::new_connect_func(ip, port, pid);
    EVENT_QUEUE.output(ctx, event, 0);
    Ok(0)
}
#[inline]
fn parse_sockaddr(sockaddr: *const sockaddr) -> Result<Option<(u32, u16)>, i64> {
    if sockaddr.is_null() {
        return Ok(None);
    }

    let family =
        unsafe { ((bpf_probe_read_user(&*sockaddr)).map_err(|e| 5i64)? as sockaddr).sa_family };
    // First we need to get the family, then we can use it to cast the sockaddr to a more specific type
    // Also, it helps filter out UDS and IPv6 connections.
    if family != AF_INET as sa_family_t {
        return Ok(None);
    }
    let sock_in_addr: *const sockaddr_in = unsafe { core::mem::transmute(sockaddr) };
    let sock_in: sockaddr_in = unsafe { bpf_probe_read_user(sock_in_addr)? };
    let ip = u32::from_be(sock_in.sin_addr.s_addr);
    let port = u16::from_be(sock_in.sin_port);
    Ok(Some((ip, port)))
}

//-------------------------

#[map()]
static ACCEPT_TID_ARGS_MAP: HashMap<u64, usize> = HashMap::with_max_entries(1024, 0);

#[kprobe(name = "snitchrs_accept")]
pub fn kprobe_accept_tcp(ctx: ProbeContext) -> u32 {
    match try_kprobe_accept_tcp(&ctx) {
        Ok(ret) => ret,
        Err(ret) => {
            let err = match ret.try_into() {
                Ok(rt) => rt,
                Err(_) => 1,
            };
            err
        }
    }
}

#[inline]
pub fn try_kprobe_accept_tcp(ctx: &ProbeContext) -> Result<u32, i64> {
    let regs = PtRegs::new(ctx.arg(0).ok_or(1u32)?);
    let sock_addr: *const sockaddr = regs.arg(1).ok_or(2i64)?;
    if sock_addr.is_null() {
        return Ok(0);
    }
    ACCEPT_TID_ARGS_MAP.insert(&bpf_get_current_pid_tgid(), &unsafe { sock_addr.addr() }, 0)?;
    Ok(0)
}

#[kretprobe(name = "snitchrs_accept_ret")]
pub fn kprobe_syscall_accept_ret(ctx: ProbeContext) -> u32 {
    match try_kprobe_syscall_accept_ret(&ctx) {
        Ok(ret) => ret,
        Err(ret) => {
            let err = match ret.try_into() {
                Ok(rt) => rt,
                Err(_) => 1,
            };
            err
        }
    }
}

#[inline]
fn try_kprobe_syscall_accept_ret(ctx: &ProbeContext) -> Result<u32, i64> {
    // int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
    // int accept4(int sockfd, struct sockaddr *addr,socklen_t *addrlen, int flags);
    let as_addr = unsafe {
        ACCEPT_TID_ARGS_MAP
            .get(&bpf_get_current_pid_tgid())
            .ok_or(1i64)?
    };
    ACCEPT_TID_ARGS_MAP.remove(&bpf_get_current_pid_tgid())?;

    let sock_addr: *const sockaddr = unsafe { (*as_addr) as *const sockaddr };

    let family =
        unsafe { ((bpf_probe_read_user(&*sock_addr)).map_err(|e| 5i64)? as sockaddr).sa_family };
    // First we need to get the family, then we can use it to cast the sockaddr to a more specific type
    // Also, it helps filter out UDS and IPv6 connections.
    if family != AF_INET as sa_family_t {
        return Ok(0);
    }
    let sock_in_addr: *const sockaddr_in = unsafe { core::mem::transmute(sock_addr) };
    let sock_in: sockaddr_in = unsafe { bpf_probe_read_user(sock_in_addr)? };
    let ip = u32::from_be(sock_in.sin_addr.s_addr);
    let port = u16::from_be(sock_in.sin_port);

    let pid = bpf_get_current_pid_tgid() as u32;
    let event = &SnitchrsEvent::new_accept_func(ip, port, pid);
    EVENT_QUEUE.output(ctx, event, 0);
    Ok(0)
}
