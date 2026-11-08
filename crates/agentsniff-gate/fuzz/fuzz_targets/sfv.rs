#![no_main]
//! RFC 8941 structured-field parsing: no panic on any input, and whatever
//! parses must serialize to text that parses again to the same text.

use agentsniff_gate::sfv;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(dict) = sfv::parse_dictionary(text) {
        let mut out = String::new();
        for (i, (key, member)) in dict.iter().enumerate() {
            if i > 0 {
                out.push_str(", ");
            }
            out.push_str(key);
            out.push('=');
            sfv::serialize_member(member, &mut out);
        }
        let again = sfv::parse_dictionary(&out).expect("serialized dictionary must parse");
        let mut out2 = String::new();
        for (i, (key, member)) in again.iter().enumerate() {
            if i > 0 {
                out2.push_str(", ");
            }
            out2.push_str(key);
            out2.push('=');
            sfv::serialize_member(member, &mut out2);
        }
        assert_eq!(out, out2, "dictionary serialization is not a fixed point");
    }
    if let Ok(item) = sfv::parse_item(text) {
        let mut out = String::new();
        sfv::serialize_item(&item, &mut out);
        let again = sfv::parse_item(&out).expect("serialized item must parse");
        let mut out2 = String::new();
        sfv::serialize_item(&again, &mut out2);
        assert_eq!(out, out2, "item serialization is not a fixed point");
    }
});
