//! eBPF TC hook for packet timing capture.
//!
//! Attached to both ingress and egress TC hooks. Captures IPv4 TCP
//! packet metadata (addresses, port, size, direction, timestamp) for
//! behavioral traffic analysis of AI agent patterns.
#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::TC_ACT_OK,
    macros::{classifier, map},
    maps::RingBuf,
    programs::TcContext,
};
use agentsniff_common::{TrafficEvent, TRAFFIC_DIR_EGRESS, TRAFFIC_DIR_INGRESS};

/// Ring buffer shared with userspace; sized for ~2 K events.
#[map]
static TRAFFIC_EVENTS: RingBuf = RingBuf::with_byte_size(
    2048 * core::mem::size_of::<TrafficEvent>() as u32,
    0,
);

const ETH_HDR_LEN: usize = 14;
const IP_HDR_LEN: usize = 20;
const IPPROTO_TCP: u8 = 6;
/// Offset of IP protocol field.
const IP_PROTO_OFF: usize = ETH_HDR_LEN + 9;
/// Offset of IP total length field.
const IP_TOTAL_LEN_OFF: usize = ETH_HDR_LEN + 2;
/// Offset of TCP destination port.
const TCP_DST_PORT_OFF: usize = ETH_HDR_LEN + IP_HDR_LEN + 2;

#[classifier]
pub fn traffic_egress(ctx: TcContext) -> i32 {
    match try_capture(&ctx, TRAFFIC_DIR_EGRESS) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_OK as i32,
    }
}

#[classifier]
pub fn traffic_ingress(ctx: TcContext) -> i32 {
    match try_capture(&ctx, TRAFFIC_DIR_INGRESS) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_OK as i32,
    }
}

#[inline(always)]
fn try_capture(ctx: &TcContext, direction: u8) -> Result<i32, ()> {
    // Only TCP.
    let proto: u8 = ctx.load(IP_PROTO_OFF).map_err(|_| ())?;
    if proto != IPPROTO_TCP {
        return Ok(TC_ACT_OK as i32);
    }

    let src_addr_be: u32 = ctx.load(ETH_HDR_LEN + 12).map_err(|_| ())?;
    let dst_addr_be: u32 = ctx.load(ETH_HDR_LEN + 16).map_err(|_| ())?;
    let dst_port_be: u16 = ctx.load(TCP_DST_PORT_OFF).map_err(|_| ())?;
    let total_len_be: u16 = ctx.load(IP_TOTAL_LEN_OFF).map_err(|_| ())?;

    if let Some(mut entry) = TRAFFIC_EVENTS.reserve::<TrafficEvent>(0) {
        let event = unsafe { entry.as_mut_ptr() };
        unsafe {
            (*event).src_addr = u32::from_be(src_addr_be);
            (*event).dst_addr = u32::from_be(dst_addr_be);
            (*event).dst_port = u16::from_be(dst_port_be);
            (*event).pkt_len = u16::from_be(total_len_be);
            (*event).direction = direction;
            (*event).timestamp_ns = aya_ebpf::helpers::bpf_ktime_get_ns();
        }
        entry.submit(0);
    }

    Ok(TC_ACT_OK as i32)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
