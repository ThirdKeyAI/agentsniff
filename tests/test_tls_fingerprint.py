"""Tests for TLS fingerprinting including JA4+."""
import struct

from agentsniff.detectors.tls_fingerprint import (
    compute_ja3_from_client_hello,
    compute_ja4_from_client_hello,
)


def _make_tls_client_hello(
    tls_version=0x0303,
    ciphers=None,
    extensions=None,
):
    """Build a minimal TLS ClientHello for testing."""
    if ciphers is None:
        ciphers = [0x1301, 0x1302, 0x1303]
    if extensions is None:
        extensions = [0, 10, 11, 13, 43, 51]  # SNI, groups, formats, sig_algs, versions, key_share

    ch = b""
    ch += struct.pack("!H", tls_version)  # Client version
    ch += b"\x00" * 32  # Random
    ch += b"\x00"  # Session ID length = 0

    cipher_data = b"".join(struct.pack("!H", c) for c in ciphers)
    ch += struct.pack("!H", len(cipher_data)) + cipher_data
    ch += b"\x01\x00"  # 1 compression method: null

    ext_data = b""
    for ext_type in extensions:
        ext_data += struct.pack("!HH", ext_type, 0)
    ch += struct.pack("!H", len(ext_data)) + ext_data

    handshake = b"\x01" + struct.pack("!I", len(ch))[1:] + ch
    record = struct.pack("!BHH", 0x16, 0x0301, len(handshake)) + handshake
    return record


def test_ja3_computation():
    hello = _make_tls_client_hello()
    ja3 = compute_ja3_from_client_hello(hello)
    assert ja3 is not None
    assert len(ja3) == 32


def test_ja3_returns_none_for_non_tls():
    assert compute_ja3_from_client_hello(b"\x00\x01\x02") is None


def test_ja4_computation():
    hello = _make_tls_client_hello()
    ja4 = compute_ja4_from_client_hello(hello)
    assert ja4 is not None
    parts = ja4.split("_")
    assert len(parts) == 3
    # Check prefix format: t[version][sni][cipher_count][ext_count]
    prefix = parts[0]
    assert prefix.startswith("t")
    assert prefix[1:3] == "12"  # TLS 1.2 = 0x0303
    assert prefix[3] == "d"  # SNI present (ext type 0 is in list)
    assert prefix[4:6] == "03"  # 3 ciphers
    assert prefix[6:8] == "06"  # 6 extensions


def test_ja4_returns_none_for_non_tls():
    assert compute_ja4_from_client_hello(b"\x00\x01\x02") is None


def test_ja4_differs_from_ja3():
    hello = _make_tls_client_hello()
    ja3 = compute_ja3_from_client_hello(hello)
    ja4 = compute_ja4_from_client_hello(hello)
    assert ja3 != ja4


def test_ja4_without_sni():
    """No SNI extension -> 'i' flag."""
    hello = _make_tls_client_hello(extensions=[10, 11, 13])  # No type 0 (SNI)
    ja4 = compute_ja4_from_client_hello(hello)
    assert ja4 is not None
    assert ja4[3] == "i"


def test_ja4_sorted_order_independence():
    """JA4 should produce same hash regardless of cipher/extension order."""
    hello1 = _make_tls_client_hello(ciphers=[0x1301, 0x1302, 0x1303])
    hello2 = _make_tls_client_hello(ciphers=[0x1303, 0x1301, 0x1302])
    ja4_1 = compute_ja4_from_client_hello(hello1)
    ja4_2 = compute_ja4_from_client_hello(hello2)
    # The sorted hash portions should be identical
    assert ja4_1.split("_")[1] == ja4_2.split("_")[1]


def test_ja4_tls13_version():
    """TLS 1.3 version should show '13'."""
    hello = _make_tls_client_hello(tls_version=0x0304)
    ja4 = compute_ja4_from_client_hello(hello)
    assert ja4[1:3] == "13"
