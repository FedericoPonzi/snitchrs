#![no_std]
#![no_main]

use aya_bpf::bindings::{TC_ACT_PIPE, TC_ACT_SHOT};
use aya_bpf::macros::{classifier, map};
use aya_bpf::maps::HashMap;
use aya_bpf::programs::TcContext;
use aya_bpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;
use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[map]
static BLOCKLIST: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

#[classifier(name = "snitchrs")]
pub fn snitchrs(ctx: TcContext) -> i32 {
    match try_snitchrs(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_SHOT,
    }
}

fn block_ip(address: u32) -> bool {
    unsafe { BLOCKLIST.get(&address).is_some() }
}

fn try_snitchrs(ctx: TcContext) -> Result<i32, ()> {
    let ethhdr: EthHdr = ctx.load(0).map_err(|_| ())?;
    match ethhdr.ether_type {
        EtherType::Ipv4 => {}
        _ => return Ok(TC_ACT_PIPE),
    }

    let ipv4hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
    let destination = u32::from_be(ipv4hdr.dst_addr);

    let action = if block_ip(destination) {
        TC_ACT_SHOT
    } else {
        TC_ACT_PIPE
    };

    info!(&ctx, "DEST {:ipv4}, ACTION {}", destination, action);

    Ok(action)
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize, offset_copy: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();

    if ctx.data() + offset + mem::size_of::<T>() > end {
        Err(())
    } else {
        Ok((start + offset_copy) as *const T)
    }
}
