//! VESA E-EDID base block (128 bytes) parser.
//!
//! Used to identify monitors by manufacturer, product, serial, and name
//! instead of Windows "Generic PnP Monitor" friendly strings.

use serde::Serialize;

const HEADER: [u8; 8] = [0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00];

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EdidInfo {
    pub manufacturer: String,
    pub product_code: u16,
    pub serial: u32,
    pub serial_string: Option<String>,
    pub name: Option<String>,
    pub year: u16,
    pub week: u8,
    pub checksum_ok: bool,
}

impl EdidInfo {
    /// Identity used to detect cloned EDIDs (splitter / dummy cloning a real panel).
    pub fn identity_key(&self) -> String {
        format!(
            "{}-{:04X}-{:08X}-{}",
            self.manufacturer,
            self.product_code,
            self.serial,
            self.serial_string.as_deref().unwrap_or("")
        )
    }

    /// Non-zero serial that is actually unique across two monitors of the same model.
    pub fn has_unique_serial(&self) -> bool {
        self.serial != 0 || self.serial_string.as_ref().is_some_and(|s| !s.is_empty())
    }
}

pub fn parse(bytes: &[u8]) -> Option<EdidInfo> {
    if bytes.len() < 128 {
        return None;
    }
    let b = &bytes[..128];
    if b[..8] != HEADER {
        return None;
    }

    let checksum_ok = b.iter().fold(0u8, |acc, x| acc.wrapping_add(*x)) == 0;
    let manufacturer = manufacturer_id(u16::from_be_bytes([b[8], b[9]]))?;
    let product_code = u16::from_le_bytes([b[10], b[11]]);
    let serial = u32::from_le_bytes([b[12], b[13], b[14], b[15]]);
    let week = b[16];
    let year = 1990 + b[17] as u16;

    let mut name = None;
    let mut serial_string = None;
    for desc in b[54..126].chunks(18) {
        if desc.len() < 18 {
            continue;
        }
        if desc[0] != 0 || desc[1] != 0 || desc[2] != 0 {
            continue;
        }
        let text = decode_descriptor_text(&desc[5..]);
        match desc[3] {
            0xFC => name = Some(text),
            0xFF => serial_string = Some(text),
            _ => {}
        }
    }

    Some(EdidInfo {
        manufacturer,
        product_code,
        serial,
        serial_string,
        name,
        year,
        week,
        checksum_ok,
    })
}

fn manufacturer_id(word: u16) -> Option<String> {
    let c1 = (((word >> 10) & 0x1f) as u8).wrapping_add(b'@');
    let c2 = (((word >> 5) & 0x1f) as u8).wrapping_add(b'@');
    let c3 = ((word & 0x1f) as u8).wrapping_add(b'@');
    if !(c1.is_ascii_uppercase() && c2.is_ascii_uppercase() && c3.is_ascii_uppercase()) {
        return None;
    }
    Some(format!("{}{}{}", c1 as char, c2 as char, c3 as char))
}

fn decode_descriptor_text(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .position(|&c| c == 0x0A || c == 0x00)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).trim().to_string()
}

/// Names / manufacturers commonly used by HDMI dummy plugs and virtual displays.
pub fn looks_like_dummy(edid: &EdidInfo) -> bool {
    let blob = format!(
        "{} {} {}",
        edid.manufacturer,
        edid.name.as_deref().unwrap_or(""),
        edid.serial_string.as_deref().unwrap_or("")
    )
    .to_lowercase();

    const NEEDLES: &[&str] = &[
        "dummy",
        "headless",
        "ghost",
        "virtual",
        "idd sample",
        "usbmmidd",
        "spacedesk",
        "parsec",
        "sunshine",
        "fake",
        "plugable",
    ];
    if NEEDLES.iter().any(|n| blob.contains(n)) {
        return true;
    }

    // Cheap dummy dongles often use a 3-letter mfg with empty name and serial 0.
    matches!(
        edid.manufacturer.as_str(),
        "AAA" | "HDF" | "MAX" | "NCP" | "UNK"
    ) && edid.serial == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dell_u2412m() -> [u8; 128] {
        // Synthetic but structurally valid EDID: manufacturer DEL, product 0x404C,
        // serial 0x12345678, name "DELL U2412M".
        let mut b = [0u8; 128];
        b[..8].copy_from_slice(&HEADER);
        // D=4, E=5, L=12 -> bits 14-10 / 9-5 / 4-0 = 0x10AC
        b[8..10].copy_from_slice(&0x10ACu16.to_be_bytes());
        b[10..12].copy_from_slice(&0x404Cu16.to_le_bytes());
        b[12..16].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        b[16] = 12;
        b[17] = (2012 - 1990) as u8;
        b[18] = 1;
        b[19] = 3;
        // descriptor 0: monitor name 0xFC
        let d = 54;
        b[d + 3] = 0xFC;
        let name = b"DELL U2412M";
        b[d + 5..d + 5 + name.len()].copy_from_slice(name);
        b[d + 5 + name.len()] = 0x0A;
        // checksum
        let sum: u8 = b[..127].iter().fold(0u8, |a, x| a.wrapping_add(*x));
        b[127] = 0u8.wrapping_sub(sum);
        b
    }

    #[test]
    fn parses_manufacturer_product_serial_name() {
        let edid = parse(&dell_u2412m()).expect("edid");
        assert_eq!(edid.manufacturer, "DEL");
        assert_eq!(edid.product_code, 0x404C);
        assert_eq!(edid.serial, 0x1234_5678);
        assert_eq!(edid.name.as_deref(), Some("DELL U2412M"));
        assert!(edid.checksum_ok);
        assert!(edid.has_unique_serial());
    }

    #[test]
    fn rejects_short_or_bad_header() {
        assert!(parse(&[0u8; 16]).is_none());
        let mut bad = dell_u2412m();
        bad[0] = 1;
        assert!(parse(&bad).is_none());
    }

    #[test]
    fn dummy_plug_heuristic() {
        let mut info = parse(&dell_u2412m()).unwrap();
        assert!(!looks_like_dummy(&info));
        info.manufacturer = "HDF".into();
        info.serial = 0;
        info.name = None;
        assert!(looks_like_dummy(&info));
        info.manufacturer = "DEL".into();
        info.name = Some("Dummy Plug".into());
        assert!(looks_like_dummy(&info));
    }
}
