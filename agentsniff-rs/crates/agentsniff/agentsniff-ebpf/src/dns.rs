//! eBPF TC egress hook for DNS query capture.
//!
//! Attaches to the TC egress path, matches UDP datagrams destined for
//! port 53, parses the DNS wire-format question section to extract the
//! query name, and pushes a `DnsEvent` into a ring buffer that the
//! userspace loader reads.
#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::TC_ACT_OK,
    macros::{classifier, map},
    maps::RingBuf,
    programs::TcContext,
};
use aya_log_ebpf::debug;
use agentsniff_common::DnsEvent;

/// Ring buffer shared with userspace; sized for ~1 K events.
#[map]
static DNS_EVENTS: RingBuf = RingBuf::with_byte_size(1024 * core::mem::size_of::<DnsEvent>() as u32, 0);

/// Ethernet header length (14 bytes, no VLAN).
const ETH_HDR_LEN: usize = 14;
/// IPv4 minimum header length (20 bytes).
const IP_HDR_LEN: usize = 20;
/// UDP header length (8 bytes).
const UDP_HDR_LEN: usize = 8;
/// DNS header length (12 bytes).
const DNS_HDR_LEN: usize = 12;

/// Offset of the IP protocol byte within an Ethernet frame.
const IP_PROTO_OFF: usize = ETH_HDR_LEN + 9;
/// Offset of the UDP destination-port field.
const UDP_DST_PORT_OFF: usize = ETH_HDR_LEN + IP_HDR_LEN + 2;
/// Offset where the DNS payload begins.
const DNS_PAYLOAD_OFF: usize = ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN + DNS_HDR_LEN;

const IPPROTO_UDP: u8 = 17;
const DNS_PORT: u16 = 53;

#[classifier]
pub fn dns_egress(ctx: TcContext) -> i32 {
    match try_dns_egress(&ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_OK as i32,
    }
}

#[inline(always)]
fn try_dns_egress(ctx: &TcContext) -> Result<i32, ()> {
    // Filter: only UDP (protocol byte in IP header).
    let proto: u8 = ctx.load(IP_PROTO_OFF).map_err(|_| ())?;
    if proto != IPPROTO_UDP {
        return Ok(TC_ACT_OK as i32);
    }

    // Filter: destination port must be 53 (big-endian).
    let dst_port_be: u16 = ctx.load(UDP_DST_PORT_OFF).map_err(|_| ())?;
    let dst_port = u16::from_be(dst_port_be);
    if dst_port != DNS_PORT {
        return Ok(TC_ACT_OK as i32);
    }

    // Read source and destination addresses from IP header.
    let src_addr: u32 = ctx.load(ETH_HDR_LEN + 12).map_err(|_| ())?;
    let dst_addr: u32 = ctx.load(ETH_HDR_LEN + 16).map_err(|_| ())?;

    // Parse DNS QNAME: length-prefixed labels ending with a 0 byte.
    let mut query_name = [0u8; 256];
    let mut query_len: usize = 0;
    let mut off = DNS_PAYLOAD_OFF;

    // Walk label sequence; convert wire format (len + bytes) to dotted string.
    loop {
        let label_len: u8 = ctx.load(off).map_err(|_| ())?;
        off += 1;

        if label_len == 0 {
            // Root label — QNAME complete.
            break;
        }

        // Insert dot separator between labels.
        if query_len > 0 && query_len < 255 {
            query_name[query_len] = b'.';
            query_len += 1;
        }

        let label_len = label_len as usize;
        // Bounds guard (verifier-visible).
        if label_len > 63 || query_len + label_len > 255 {
            break;
        }

        // Copy label bytes one at a time (bounded loop for verifier).
        for i in 0..64usize {
            if i >= label_len {
                break;
            }
            let b: u8 = ctx.load(off + i).map_err(|_| ())?;
            query_name[query_len] = b;
            query_len += 1;
        }
        off += label_len;
    }

    // Submit event to ring buffer.
    if let Some(mut entry) = DNS_EVENTS.reserve::<DnsEvent>(0) {
        let event = unsafe { entry.as_mut_ptr() };
        unsafe {
            (*event).src_addr = u32::from_be(src_addr);
            (*event).dst_addr = u32::from_be(dst_addr);
            (*event).query_name = query_name;
            (*event).query_len = query_len as u16;
            (*event).timestamp_ns = aya_ebpf::helpers::bpf_ktime_get_ns();
        }
        entry.submit(0);
        debug!(&ctx, "dns: captured query len={}", query_len);
    }

    Ok(TC_ACT_OK as i32)
}

// Required panic handler for no_std targets.
#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
