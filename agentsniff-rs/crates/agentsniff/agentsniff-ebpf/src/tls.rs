//! eBPF TC egress hook for TLS ClientHello capture.
//!
//! Matches TCP packets whose payload begins with `0x16 0x03` (TLS record
//! type Handshake + legacy version byte), parses cipher suites and
//! extension types from the ClientHello body, and pushes a `TlsEvent`
//! into a ring buffer.
#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::TC_ACT_OK,
    macros::{classifier, map},
    maps::RingBuf,
    programs::TcContext,
};
use aya_log_ebpf::debug;
use agentsniff_common::TlsEvent;

/// Ring buffer shared with userspace.
#[map]
static TLS_EVENTS: RingBuf = RingBuf::with_byte_size(
    512 * core::mem::size_of::<TlsEvent>() as u32,
    0,
);

const ETH_HDR_LEN: usize = 14;
const IP_HDR_LEN: usize = 20;

/// Offset of IP protocol field.
const IP_PROTO_OFF: usize = ETH_HDR_LEN + 9;
/// Offset of TCP data-offset nibble (high 4 bits give header length in 32-bit words).
const TCP_DOFF_OFF: usize = ETH_HDR_LEN + IP_HDR_LEN + 12;
/// Offset of TCP source port.
const TCP_SRC_PORT_OFF: usize = ETH_HDR_LEN + IP_HDR_LEN;
/// Offset of TCP destination port.
const TCP_DST_PORT_OFF: usize = ETH_HDR_LEN + IP_HDR_LEN + 2;

const IPPROTO_TCP: u8 = 6;

/// TLS record type for Handshake messages.
const TLS_RECORD_HANDSHAKE: u8 = 0x16;
/// TLS legacy version major byte.
const TLS_LEGACY_VERSION_MAJOR: u8 = 0x03;
/// TLS Handshake type for ClientHello.
const TLS_HANDSHAKE_CLIENT_HELLO: u8 = 0x01;

/// Maximum number of cipher suites / extensions we record.
const MAX_CIPHERS: usize = 64;
const MAX_EXTENSIONS: usize = 64;

#[classifier]
pub fn tls_egress(ctx: TcContext) -> i32 {
    match try_tls_egress(&ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_OK as i32,
    }
}

#[inline(always)]
fn try_tls_egress(ctx: &TcContext) -> Result<i32, ()> {
    // Only process TCP.
    let proto: u8 = ctx.load(IP_PROTO_OFF).map_err(|_| ())?;
    if proto != IPPROTO_TCP {
        return Ok(TC_ACT_OK as i32);
    }

    // Compute TCP header length from data-offset field.
    let doff_byte: u8 = ctx.load(TCP_DOFF_OFF).map_err(|_| ())?;
    let tcp_hdr_len = ((doff_byte >> 4) as usize) * 4;
    if tcp_hdr_len < 20 {
        return Ok(TC_ACT_OK as i32);
    }

    let tcp_payload_off = ETH_HDR_LEN + IP_HDR_LEN + tcp_hdr_len;

    // Check TLS record header: content type 0x16, legacy version 0x03 ?x.
    let content_type: u8 = ctx.load(tcp_payload_off).map_err(|_| ())?;
    let version_major: u8 = ctx.load(tcp_payload_off + 1).map_err(|_| ())?;
    if content_type != TLS_RECORD_HANDSHAKE || version_major != TLS_LEGACY_VERSION_MAJOR {
        return Ok(TC_ACT_OK as i32);
    }

    // Ensure it is a ClientHello (handshake type byte at offset +5).
    let hs_type: u8 = ctx.load(tcp_payload_off + 5).map_err(|_| ())?;
    if hs_type != TLS_HANDSHAKE_CLIENT_HELLO {
        return Ok(TC_ACT_OK as i32);
    }

    // Read legacy TLS record version (used for TlsEvent.tls_version).
    let tls_version_be: u16 = ctx.load(tcp_payload_off + 1).map_err(|_| ())?;
    let tls_version = u16::from_be(tls_version_be);

    // Src/dst addresses from IP header.
    let src_addr_be: u32 = ctx.load(ETH_HDR_LEN + 12).map_err(|_| ())?;
    let dst_addr_be: u32 = ctx.load(ETH_HDR_LEN + 16).map_err(|_| ())?;
    let src_addr = u32::from_be(src_addr_be);
    let dst_addr = u32::from_be(dst_addr_be);

    let dst_port_be: u16 = ctx.load(TCP_DST_PORT_OFF).map_err(|_| ())?;
    let dst_port = u16::from_be(dst_port_be);

    // ClientHello layout after the 4-byte handshake header:
    //   2 bytes: client_version
    //   32 bytes: random
    //   1 byte: session_id length
    //   N bytes: session_id
    //   2 bytes: cipher_suites length
    //   ... cipher suites (2 bytes each)
    //   1 byte: compression_methods length
    //   ...
    //   2 bytes: extensions length (optional)
    //   ...
    //
    // Base offset of ClientHello body = tcp_payload_off + 5 (record hdr) + 4 (hs hdr)
    let ch_base = tcp_payload_off + 5 + 4;

    // Skip client_version (2) + random (32).
    let sid_len_off = ch_base + 2 + 32;
    let sid_len: u8 = ctx.load(sid_len_off).map_err(|_| ())?;

    // Cipher suites length field.
    let cs_len_off = sid_len_off + 1 + sid_len as usize;
    let cs_len_be: u16 = ctx.load(cs_len_off).map_err(|_| ())?;
    let cs_len = u16::from_be(cs_len_be) as usize;

    // Collect up to MAX_CIPHERS cipher suite values.
    let mut cipher_suites = [0u16; MAX_CIPHERS];
    let mut cipher_count: usize = 0;
    let cs_data_off = cs_len_off + 2;

    for i in 0..MAX_CIPHERS {
        if i * 2 >= cs_len {
            break;
        }
        let cs_be: u16 = ctx.load(cs_data_off + i * 2).map_err(|_| ())?;
        cipher_suites[i] = u16::from_be(cs_be);
        cipher_count += 1;
    }

    // Skip compression methods.
    let comp_len_off = cs_data_off + cs_len;
    let comp_len: u8 = ctx.load(comp_len_off).map_err(|_| ())?;

    // Extensions section.
    let ext_total_off = comp_len_off + 1 + comp_len as usize;
    let ext_total_be: u16 = ctx.load(ext_total_off).map_err(|_| ())?;
    let ext_total = u16::from_be(ext_total_be) as usize;

    // Walk extensions and collect type values.
    let mut extensions = [0u16; MAX_EXTENSIONS];
    let mut extension_count: usize = 0;
    let mut ext_off = ext_total_off + 2;
    let ext_end = ext_off + ext_total;

    for _ in 0..MAX_EXTENSIONS {
        if ext_off + 4 > ext_end {
            break;
        }
        let ext_type_be: u16 = ctx.load(ext_off).map_err(|_| ())?;
        let ext_type = u16::from_be(ext_type_be);
        let ext_data_len_be: u16 = ctx.load(ext_off + 2).map_err(|_| ())?;
        let ext_data_len = u16::from_be(ext_data_len_be) as usize;

        if extension_count < MAX_EXTENSIONS {
            extensions[extension_count] = ext_type;
            extension_count += 1;
        }

        ext_off += 4 + ext_data_len;
    }

    // Submit event.
    if let Some(mut entry) = TLS_EVENTS.reserve::<TlsEvent>(0) {
        let event = unsafe { entry.as_mut_ptr() };
        unsafe {
            (*event).src_addr = src_addr;
            (*event).dst_addr = dst_addr;
            (*event).dst_port = dst_port;
            (*event).tls_version = tls_version;
            (*event).cipher_suites = cipher_suites;
            (*event).cipher_count = cipher_count as u8;
            (*event).extensions = extensions;
            (*event).extension_count = extension_count as u8;
            (*event).timestamp_ns = aya_ebpf::helpers::bpf_ktime_get_ns();
        }
        entry.submit(0);
        debug!(
            &ctx,
            "tls: ClientHello ciphers={} exts={}", cipher_count, extension_count
        );
    }

    Ok(TC_ACT_OK as i32)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
