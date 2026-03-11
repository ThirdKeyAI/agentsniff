//! eBPF kprobe on `tcp_v4_connect` for outbound connection tracking.
//!
//! Fires whenever a process calls `tcp_v4_connect(2)`, captures the
//! destination address and port from the `sockaddr_in` argument, and
//! pushes a `ConnEvent` into a ring buffer.
#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{kprobe, map},
    maps::RingBuf,
    programs::ProbeContext,
};
use aya_log_ebpf::debug;
use agentsniff_common::{ConnEvent, TCP_SYN_SENT};

/// Ring buffer shared with userspace.
#[map]
static CONN_EVENTS: RingBuf = RingBuf::with_byte_size(
    1024 * core::mem::size_of::<ConnEvent>() as u32,
    0,
);

/// Byte offset of `sin_port` in a `sockaddr_in` (after `sin_family: u16`).
const SOCKADDR_IN_PORT_OFF: usize = 2;
/// Byte offset of `sin_addr` in a `sockaddr_in`.
const SOCKADDR_IN_ADDR_OFF: usize = 4;

/// kprobe entry for `tcp_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)`.
///
/// arg0 = `struct sock *sk`  (unused here; source address lives in sk_rcv_saddr)
/// arg1 = `struct sockaddr *uaddr`  — pointer to userspace `sockaddr_in`
#[kprobe]
pub fn tcp_v4_connect(ctx: ProbeContext) -> u32 {
    match try_tcp_v4_connect(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

#[inline(always)]
fn try_tcp_v4_connect(ctx: &ProbeContext) -> Result<u32, ()> {
    // arg1 is the pointer to `struct sockaddr_in` in userspace.
    let uaddr: *const u8 = ctx.arg(1).ok_or(())?;

    // Read destination port (big-endian u16 at offset 2).
    let port_be: u16 = unsafe {
        let ptr = uaddr.add(SOCKADDR_IN_PORT_OFF) as *const u16;
        aya_ebpf::helpers::bpf_probe_read_user(ptr).map_err(|_| ())?
    };
    let dst_port = u16::from_be(port_be);

    // Read destination address (u32 at offset 4, already network byte order).
    let addr_be: u32 = unsafe {
        let ptr = uaddr.add(SOCKADDR_IN_ADDR_OFF) as *const u32;
        aya_ebpf::helpers::bpf_probe_read_user(ptr).map_err(|_| ())?
    };
    let dst_addr = u32::from_be(addr_be);

    // Submit event.
    if let Some(mut entry) = CONN_EVENTS.reserve::<ConnEvent>(0) {
        let event = unsafe { entry.as_mut_ptr() };
        unsafe {
            (*event).src_addr = 0; // filled in by userspace from pid/netns if needed
            (*event).dst_addr = dst_addr;
            (*event).dst_port = dst_port;
            (*event).state = TCP_SYN_SENT;
            (*event).timestamp_ns = 0; // bpf_ktime_get_ns() would go here
        }
        entry.submit(0);
        debug!(ctx, "connect: dst={}:{}", dst_addr, dst_port);
    }

    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
