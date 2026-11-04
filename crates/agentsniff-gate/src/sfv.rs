//! Minimal RFC 8941 Structured Field Values: the subset HTTP Message
//! Signatures (RFC 9421) and Web Bot Auth need.
//!
//! Parses Dictionaries, Inner Lists, Items and Parameters, and re-serializes
//! them canonically so a signature base can be rebuilt byte for byte. Input is
//! network-derived, so every parser enforces member and length budgets.

use base64::Engine;

/// Largest field value this module will parse.
pub const MAX_FIELD_BYTES: usize = 8 * 1024;
/// Most dictionary members, inner-list items, or parameters accepted.
const MAX_MEMBERS: usize = 32;

#[derive(Debug, Clone, PartialEq)]
pub enum BareItem {
    Integer(i64),
    Decimal(f64),
    String(String),
    Token(String),
    ByteSeq(Vec<u8>),
    Boolean(bool),
}

pub type Parameters = Vec<(String, BareItem)>;

#[derive(Debug, Clone, PartialEq)]
pub struct Item {
    pub bare: BareItem,
    pub params: Parameters,
}

#[derive(Debug, Clone, PartialEq)]
pub struct InnerList {
    pub items: Vec<Item>,
    pub params: Parameters,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Member {
    Item(Item),
    InnerList(InnerList),
}

/// Ordered dictionary. A repeated key replaces the earlier value in place,
/// as RFC 8941 section 4.2.2 requires.
pub type Dictionary = Vec<(String, Member)>;

pub fn param<'a>(params: &'a Parameters, key: &str) -> Option<&'a BareItem> {
    params.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

pub fn dict_get<'a>(dict: &'a Dictionary, key: &str) -> Option<&'a Member> {
    dict.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

struct Parser<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(input: &'a str) -> Result<Self, &'static str> {
        if input.len() > MAX_FIELD_BYTES {
            return Err("field_too_large");
        }
        Ok(Self {
            input: input.as_bytes(),
            pos: 0,
        })
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.pos).copied()
    }

    fn next(&mut self) -> Option<u8> {
        let c = self.peek()?;
        self.pos += 1;
        Some(c)
    }

    fn eof(&self) -> bool {
        self.pos >= self.input.len()
    }

    fn skip_sp(&mut self) {
        while self.peek() == Some(b' ') {
            self.pos += 1;
        }
    }

    fn skip_ows(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t')) {
            self.pos += 1;
        }
    }

    fn key(&mut self) -> Result<String, &'static str> {
        match self.peek() {
            Some(c) if c.is_ascii_lowercase() || c == b'*' => {}
            _ => return Err("bad_key"),
        }
        let start = self.pos;
        while let Some(c) = self.peek() {
            if c.is_ascii_lowercase()
                || c.is_ascii_digit()
                || matches!(c, b'_' | b'-' | b'.' | b'*')
            {
                self.pos += 1;
            } else {
                break;
            }
        }
        Ok(String::from_utf8_lossy(&self.input[start..self.pos]).into_owned())
    }

    fn parameters(&mut self) -> Result<Parameters, &'static str> {
        let mut params: Parameters = Vec::new();
        while self.peek() == Some(b';') {
            self.pos += 1;
            self.skip_sp();
            let key = self.key()?;
            let value = if self.peek() == Some(b'=') {
                self.pos += 1;
                self.bare_item()?
            } else {
                BareItem::Boolean(true)
            };
            if let Some(slot) = params.iter_mut().find(|(k, _)| *k == key) {
                slot.1 = value;
            } else {
                if params.len() >= MAX_MEMBERS {
                    return Err("too_many_parameters");
                }
                params.push((key, value));
            }
        }
        Ok(params)
    }

    fn item(&mut self) -> Result<Item, &'static str> {
        let bare = self.bare_item()?;
        let params = self.parameters()?;
        Ok(Item { bare, params })
    }

    fn member(&mut self) -> Result<Member, &'static str> {
        if self.peek() == Some(b'(') {
            self.inner_list().map(Member::InnerList)
        } else {
            self.item().map(Member::Item)
        }
    }

    fn inner_list(&mut self) -> Result<InnerList, &'static str> {
        if self.next() != Some(b'(') {
            return Err("bad_inner_list");
        }
        let mut items = Vec::new();
        loop {
            self.skip_sp();
            if self.peek() == Some(b')') {
                self.pos += 1;
                let params = self.parameters()?;
                return Ok(InnerList { items, params });
            }
            if items.len() >= MAX_MEMBERS {
                return Err("too_many_items");
            }
            items.push(self.item()?);
            match self.peek() {
                Some(b' ' | b')') => {}
                _ => return Err("bad_inner_list"),
            }
        }
    }

    fn bare_item(&mut self) -> Result<BareItem, &'static str> {
        match self.peek() {
            Some(b'-') | Some(b'0'..=b'9') => self.number(),
            Some(b'"') => self.string().map(BareItem::String),
            Some(b':') => self.byte_seq().map(BareItem::ByteSeq),
            Some(b'?') => self.boolean().map(BareItem::Boolean),
            Some(c) if c.is_ascii_alphabetic() || c == b'*' => self.token().map(BareItem::Token),
            _ => Err("bad_item"),
        }
    }

    fn number(&mut self) -> Result<BareItem, &'static str> {
        let start = self.pos;
        let negative = self.peek() == Some(b'-');
        if negative {
            self.pos += 1;
        }
        let digits_start = self.pos;
        let mut seen_dot = false;
        while let Some(c) = self.peek() {
            if c.is_ascii_digit() {
                self.pos += 1;
            } else if c == b'.' && !seen_dot {
                seen_dot = true;
                self.pos += 1;
            } else {
                break;
            }
        }
        let text = std::str::from_utf8(&self.input[start..self.pos]).map_err(|_| "bad_number")?;
        let unsigned = &self.input[digits_start..self.pos];
        if unsigned.is_empty() || !unsigned[0].is_ascii_digit() {
            return Err("bad_number");
        }
        if seen_dot {
            let (whole, frac) = text
                .trim_start_matches('-')
                .split_once('.')
                .unwrap_or(("", ""));
            if whole.len() > 12 || frac.is_empty() || frac.len() > 3 {
                return Err("bad_decimal");
            }
            text.parse::<f64>()
                .map(BareItem::Decimal)
                .map_err(|_| "bad_decimal")
        } else {
            if unsigned.len() > 15 {
                return Err("integer_too_long");
            }
            text.parse::<i64>()
                .map(BareItem::Integer)
                .map_err(|_| "bad_integer")
        }
    }

    fn string(&mut self) -> Result<String, &'static str> {
        if self.next() != Some(b'"') {
            return Err("bad_string");
        }
        let mut out = String::new();
        loop {
            match self.next() {
                Some(b'\\') => match self.next() {
                    Some(c @ (b'"' | b'\\')) => out.push(c as char),
                    _ => return Err("bad_string_escape"),
                },
                Some(b'"') => return Ok(out),
                Some(c) if (0x20..=0x7e).contains(&c) => out.push(c as char),
                _ => return Err("bad_string"),
            }
        }
    }

    fn token(&mut self) -> Result<String, &'static str> {
        let start = self.pos;
        self.pos += 1;
        while let Some(c) = self.peek() {
            if is_tchar(c) || c == b':' || c == b'/' {
                self.pos += 1;
            } else {
                break;
            }
        }
        Ok(String::from_utf8_lossy(&self.input[start..self.pos]).into_owned())
    }

    fn byte_seq(&mut self) -> Result<Vec<u8>, &'static str> {
        if self.next() != Some(b':') {
            return Err("bad_byte_sequence");
        }
        let start = self.pos;
        while let Some(c) = self.peek() {
            if c == b':' {
                break;
            }
            if !(c.is_ascii_alphanumeric() || matches!(c, b'+' | b'/' | b'=')) {
                return Err("bad_byte_sequence");
            }
            self.pos += 1;
        }
        if self.next() != Some(b':') {
            return Err("bad_byte_sequence");
        }
        let encoded = &self.input[start..self.pos - 1];
        base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(encoded))
            .map_err(|_| "bad_byte_sequence")
    }

    fn boolean(&mut self) -> Result<bool, &'static str> {
        self.pos += 1;
        match self.next() {
            Some(b'1') => Ok(true),
            Some(b'0') => Ok(false),
            _ => Err("bad_boolean"),
        }
    }
}

fn is_tchar(c: u8) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

/// Parse a Dictionary field value (RFC 8941 section 4.2.2).
pub fn parse_dictionary(input: &str) -> Result<Dictionary, &'static str> {
    let mut p = Parser::new(input)?;
    p.skip_sp();
    let mut dict: Dictionary = Vec::new();
    if p.eof() {
        return Ok(dict);
    }
    loop {
        let key = p.key()?;
        let member = if p.peek() == Some(b'=') {
            p.pos += 1;
            p.member()?
        } else {
            Member::Item(Item {
                bare: BareItem::Boolean(true),
                params: p.parameters()?,
            })
        };
        if let Some(slot) = dict.iter_mut().find(|(k, _)| *k == key) {
            slot.1 = member;
        } else {
            if dict.len() >= MAX_MEMBERS {
                return Err("too_many_members");
            }
            dict.push((key, member));
        }
        p.skip_ows();
        if p.eof() {
            return Ok(dict);
        }
        if p.next() != Some(b',') {
            return Err("bad_dictionary");
        }
        p.skip_ows();
        if p.eof() {
            return Err("trailing_comma");
        }
    }
}

/// Parse a single Item field value (RFC 8941 section 4.2.3).
pub fn parse_item(input: &str) -> Result<Item, &'static str> {
    let mut p = Parser::new(input)?;
    p.skip_sp();
    let item = p.item()?;
    p.skip_sp();
    if !p.eof() {
        return Err("trailing_characters");
    }
    Ok(item)
}

pub fn serialize_bare_item(item: &BareItem, out: &mut String) {
    match item {
        BareItem::Integer(n) => out.push_str(&n.to_string()),
        BareItem::Decimal(d) => {
            let rounded = (d * 1000.0).round() / 1000.0;
            let mut text = format!("{rounded:.3}");
            while text.ends_with('0') && !text.ends_with(".0") {
                text.pop();
            }
            out.push_str(&text);
        }
        BareItem::String(s) => {
            out.push('"');
            for c in s.chars() {
                if c == '"' || c == '\\' {
                    out.push('\\');
                }
                out.push(c);
            }
            out.push('"');
        }
        BareItem::Token(t) => out.push_str(t),
        BareItem::ByteSeq(bytes) => {
            out.push(':');
            out.push_str(&base64::engine::general_purpose::STANDARD.encode(bytes));
            out.push(':');
        }
        BareItem::Boolean(b) => out.push_str(if *b { "?1" } else { "?0" }),
    }
}

pub fn serialize_params(params: &Parameters, out: &mut String) {
    for (key, value) in params {
        out.push(';');
        out.push_str(key);
        if *value != BareItem::Boolean(true) {
            out.push('=');
            serialize_bare_item(value, out);
        }
    }
}

pub fn serialize_item(item: &Item, out: &mut String) {
    serialize_bare_item(&item.bare, out);
    serialize_params(&item.params, out);
}

pub fn serialize_inner_list(list: &InnerList, out: &mut String) {
    out.push('(');
    for (index, item) in list.items.iter().enumerate() {
        if index > 0 {
            out.push(' ');
        }
        serialize_item(item, out);
    }
    out.push(')');
    serialize_params(&list.params, out);
}

pub fn serialize_member(member: &Member, out: &mut String) {
    match member {
        Member::Item(item) => serialize_item(item, out),
        Member::InnerList(list) => serialize_inner_list(list, out),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_input_round_trips() {
        let raw = r#"sig2=("@authority" "signature-agent";key="agent2");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=4889289600;nonce="n9p4";tag="web-bot-auth""#;
        let dict = parse_dictionary(raw).unwrap();
        assert_eq!(dict.len(), 1);
        let mut out = String::from("sig2=");
        serialize_member(&dict[0].1, &mut out);
        assert_eq!(out, raw);
    }

    #[test]
    fn byte_sequence_and_bare_keys() {
        let dict = parse_dictionary("a=:AQID:, b, c=?0;x").unwrap();
        assert_eq!(
            dict[0].1,
            Member::Item(Item {
                bare: BareItem::ByteSeq(vec![1, 2, 3]),
                params: vec![]
            })
        );
        assert_eq!(
            dict[1].1,
            Member::Item(Item {
                bare: BareItem::Boolean(true),
                params: vec![]
            })
        );
        assert!(matches!(&dict[2].1, Member::Item(item) if item.bare == BareItem::Boolean(false)));
    }

    #[test]
    fn rejects_malformed_and_oversized_input() {
        assert!(parse_dictionary("a=1,").is_err());
        assert!(parse_dictionary("A=1").is_err());
        assert!(parse_dictionary("a=\"unterminated").is_err());
        assert!(parse_dictionary("a=1234567890123456").is_err());
        assert!(parse_dictionary(&"a".repeat(MAX_FIELD_BYTES + 1)).is_err());
        let many: Vec<String> = (0..40).map(|i| format!("k{i}=1")).collect();
        assert!(parse_dictionary(&many.join(",")).is_err());
    }

    #[test]
    fn duplicate_keys_overwrite_in_place() {
        let dict = parse_dictionary("a=1, b=2, a=3").unwrap();
        assert_eq!(dict.len(), 2);
        assert!(matches!(&dict[0].1, Member::Item(item) if item.bare == BareItem::Integer(3)));
    }

    #[test]
    fn legacy_string_item() {
        let item = parse_item(r#""https://signature-agent.test""#).unwrap();
        assert_eq!(
            item.bare,
            BareItem::String("https://signature-agent.test".into())
        );
    }
}
