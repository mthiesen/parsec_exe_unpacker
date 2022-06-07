use crate::dos_exe::{Info, SegmentOffsetPtr, MZ_HEADER_SIGNATURE, PAGE_SIZE, PARAGRAPH_SIZE};
use byteorder::{ByteOrder, LittleEndian};
use eyre::bail;
use eyre::Result;
use eyre::WrapErr;
use std::io::{ErrorKind, Read};

// -------------------------------------------------------------------------------------------------

const HEADER_PARAGRAPH_COUNT: usize = 2;
pub const SIZE: usize = PARAGRAPH_SIZE * HEADER_PARAGRAPH_COUNT;

// -------------------------------------------------------------------------------------------------

pub fn parse_header<R: Read>(mut reader: R) -> Result<Info> {
    let header_data = {
        let mut buffer = [0u8; SIZE];
        reader
            .read_exact(&mut buffer)
            .wrap_err("Unable to read exe header.")?;
        buffer
    };

    if LittleEndian::read_u16(&header_data[0..2]) != MZ_HEADER_SIGNATURE {
        bail!("Data is not a valid exe header.");
    }

    let load_module_len = {
        let file_page_count = LittleEndian::read_u16(&header_data[0x04..]) as usize;
        let last_page_len = LittleEndian::read_u16(&header_data[0x02..]) as usize;

        if file_page_count == 0 || last_page_len >= PAGE_SIZE {
            bail!("Data is not a valid exe header.");
        }

        if last_page_len > 0 {
            (file_page_count - 1) * PAGE_SIZE + last_page_len - SIZE
        } else {
            file_page_count * PAGE_SIZE
        }
    };

    let total_alloc_len = {
        let min_alloc = LittleEndian::read_u16(&header_data[0x0a..]) as usize;
        load_module_len + min_alloc * PARAGRAPH_SIZE
    };

    let initial_stack_ptr = SegmentOffsetPtr::new(
        LittleEndian::read_u16(&header_data[0x0e..]),
        LittleEndian::read_u16(&header_data[0x10..]),
    );
    // It is ok for the stack ptr to point as the first byte after the allocated memory because
    // PUSH decrements first and writes second. Therefore the ">" test instead of ">=".
    if initial_stack_ptr.to_linear() > total_alloc_len {
        bail!("Data is not a valid exe header.");
    }

    let entry_point = SegmentOffsetPtr::new(
        LittleEndian::read_u16(&header_data[0x16..]),
        LittleEndian::read_u16(&header_data[0x14..]),
    );
    if entry_point.to_linear() >= load_module_len {
        bail!("Data is not a valid exe header.");
    }

    const PARSEC_SIGNATURE: &str = "PRSC";
    if &header_data[0x1c..0x20] != PARSEC_SIGNATURE.as_bytes() {
        bail!("Data is not a valid parsec exe header.");
    }

    let relocation_item_count = LittleEndian::read_u16(&header_data[0x06..]);
    if relocation_item_count > 0 {
        bail!("Data is not a valid parsec exe header.");
    }

    let header_paragraph_count = LittleEndian::read_u16(&header_data[0x08..]);
    if header_paragraph_count as usize != HEADER_PARAGRAPH_COUNT {
        bail!("Data is not a valid parsec exe header.");
    }

    Ok(Info {
        load_module_len,
        total_alloc_len,
        initial_stack_ptr,
        entry_point,
    })
}

pub fn verify_footer<R: Read>(mut reader: R) -> Result<bool> {
    const FOOTER: &str = "\x0d\x0a\
                          A PARSEC Production\x0d\x0a\
                          This is the end of the file!\x0d\x0a\
                          Das ist das Ende der Datei!\x0d\x0a\
                          C'est le fin du fichier!\x0d\x0a\x00";

    let mut footer_buffer = [0u8; 109];
    match reader.read_exact(&mut footer_buffer[..]) {
        Ok(_) => Ok(&footer_buffer[..] == FOOTER.as_bytes()),
        Err(err) => {
            if err.kind() == ErrorKind::UnexpectedEof {
                Ok(false)
            } else {
                bail!("Failed to read footer data.");
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use assert_matches::assert_matches;

    #[test]
    fn parse_correctly() {
        const HEADER: [u8; SIZE] = [
            0x4d, 0x5a, 0xca, 0x00, 0x9b, 0x00, 0x00, 0x00, 0x02, 0x00, 0x04, 0x13, 0xff, 0xff,
            0x4b, 0x13, 0x00, 0x01, 0x00, 0x00, 0xd0, 0x01, 0x29, 0x13, 0x1c, 0x00, 0x00, 0x00,
            0x50, 0x52, 0x53, 0x43,
        ];
        let info = parse_header(&HEADER[..]).unwrap();
        assert_eq!(79018, info.load_module_len);
        assert_eq!(156906, info.total_alloc_len);
        assert_eq!(SegmentOffsetPtr::new(4939, 256), info.initial_stack_ptr);
        assert_eq!(SegmentOffsetPtr::new(4905, 464), info.entry_point);
    }
    #[test]
    fn module_len_when_last_page_len_is_0() {
        const HEADER: [u8; SIZE] = [
            0x4d, 0x5a, 0x00, 0x00, 0x9b, 0x00, 0x00, 0x00, 0x02, 0x00, 0x04, 0x13, 0xff, 0xff,
            0x4b, 0x13, 0x00, 0x01, 0x00, 0x00, 0xd0, 0x01, 0x29, 0x13, 0x1c, 0x00, 0x00, 0x00,
            0x50, 0x52, 0x53, 0x43,
        ];
        let info = parse_header(&HEADER[..]).unwrap();
        // It is a special case if the last page length is 0. In that case the last page length is interpreted as 512 not 0.
        assert_eq!(0x9b * PAGE_SIZE, info.load_module_len);
    }

    #[test]
    fn invalid_last_page_len() {
        {
            const HEADER: [u8; SIZE] = [
                0x4d, 0x5a, 0xff, 0xff, 0x9b, 0x00, 0x00, 0x00, 0x02, 0x00, 0x04, 0x13, 0xff, 0xff,
                0x4b, 0x13, 0x00, 0x01, 0x00, 0x00, 0xd0, 0x01, 0x29, 0x13, 0x1c, 0x00, 0x00, 0x00,
                0x50, 0x52, 0x53, 0x43,
            ];
            assert!(parse_header(&HEADER[..]).is_err());
        }
        {
            const HEADER: [u8; SIZE] = [
                0x4d, 0x5a, 0x00, 0x02, 0x9b, 0x00, 0x00, 0x00, 0x02, 0x00, 0x04, 0x13, 0xff, 0xff,
                0x4b, 0x13, 0x00, 0x01, 0x00, 0x00, 0xd0, 0x01, 0x29, 0x13, 0x1c, 0x00, 0x00, 0x00,
                0x50, 0x52, 0x53, 0x43,
            ];
            assert!(parse_header(&HEADER[..]).is_err());
        }
    }

    #[test]
    fn not_enough_data() {
        let buffer = [0u8; 1];
        assert!(parse_header(&buffer[..]).is_err());
    }

    #[test]
    fn exe_header_signature_missing() {
        const HEADER: [u8; SIZE] = [
            0x00, 0x00, 0xca, 0x00, 0x9b, 0x00, 0x00, 0x00, 0x02, 0x00, 0x04, 0x13, 0xff, 0xff,
            0x4b, 0x13, 0x00, 0x01, 0x00, 0x00, 0xd0, 0x01, 0x29, 0x13, 0x1c, 0x00, 0x00, 0x00,
            0x50, 0x52, 0x53, 0x43,
        ];
        assert!(parse_header(&HEADER[..]).is_err());
    }

    #[test]
    fn parsec_signature_missing() {
        const HEADER: [u8; SIZE] = [
            0x4d, 0x5a, 0xca, 0x00, 0x9b, 0x00, 0x00, 0x00, 0x02, 0x00, 0x04, 0x13, 0xff, 0xff,
            0x4b, 0x13, 0x00, 0x01, 0x00, 0x00, 0xd0, 0x01, 0x29, 0x13, 0x1c, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        assert!(parse_header(&HEADER[..]).is_err());
    }

    #[test]
    fn has_relocation_table() {
        const HEADER: [u8; SIZE] = [
            0x4d, 0x5a, 0xca, 0x00, 0x9b, 0x00, 0x05, 0x00, 0x02, 0x00, 0x04, 0x13, 0xff, 0xff,
            0x4b, 0x13, 0x00, 0x01, 0x00, 0x00, 0xd0, 0x01, 0x29, 0x13, 0x1c, 0x00, 0x00, 0x00,
            0x50, 0x52, 0x53, 0x43,
        ];
        assert!(parse_header(&HEADER[..]).is_err());
    }

    #[test]
    fn header_wrong_size() {
        const HEADER: [u8; SIZE] = [
            0x4d, 0x5a, 0xca, 0x00, 0x9b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0x13, 0xff, 0xff,
            0x4b, 0x13, 0x00, 0x01, 0x00, 0x00, 0xd0, 0x01, 0x29, 0x13, 0x1c, 0x00, 0x00, 0x00,
            0x50, 0x52, 0x53, 0x43,
        ];
        assert!(parse_header(&HEADER[..]).is_err());
    }

    #[test]
    fn invalid_page_count() {
        const HEADER: [u8; SIZE] = [
            0x4d, 0x5a, 0xca, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x04, 0x13, 0xff, 0xff,
            0x4b, 0x13, 0x00, 0x01, 0x00, 0x00, 0xd0, 0x01, 0x29, 0x13, 0x1c, 0x00, 0x00, 0x00,
            0x50, 0x52, 0x53, 0x43,
        ];
        assert!(parse_header(&HEADER[..]).is_err());
    }

    #[test]
    fn initial_stack_ptr_out_of_bounds() {
        const HEADER: [u8; SIZE] = [
            0x4d, 0x5a, 0xca, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x04, 0x13, 0xff, 0xff,
            0xff, 0xff, 0x00, 0x01, 0x00, 0x00, 0xd0, 0x01, 0x29, 0x13, 0x1c, 0x00, 0x00, 0x00,
            0x50, 0x52, 0x53, 0x43,
        ];
        assert!(parse_header(&HEADER[..]).is_err());
    }

    #[test]
    fn entry_point_out_of_bounds() {
        const HEADER: [u8; SIZE] = [
            0x4d, 0x5a, 0xca, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x04, 0x13, 0xff, 0xff,
            0x4b, 0x13, 0x00, 0x01, 0x00, 0x00, 0xd0, 0x01, 0xff, 0xff, 0x1c, 0x00, 0x00, 0x00,
            0x50, 0x52, 0x53, 0x43,
        ];
        assert!(parse_header(&HEADER[..]).is_err());
    }

    #[test]
    fn not_enough_data_for_footer() {
        const FOOTER: &str = "\x0d\x0a\
                              A PARSEC Production\x0d\x0a\
                              This is the end of the file!\x0d\x0a\
                              Das ist das Ende der Datei!\x0d\x0a";
        let result = verify_footer(FOOTER.as_bytes());
        assert_matches!(result, Ok(false));
    }

    #[test]
    fn invalid_footer_data() {
        const FOOTER: &str = "\x0d\x0a\
                              A PARSEC Production\x0d\x0a\
                              This is the end of the file!\x0d\x0a\
                              Das ist das Ende der Datei!\x0d\x0a\
                              C'est le fin du fichxxx!\x0d\x0a\x00";
        let result = verify_footer(FOOTER.as_bytes());
        assert_matches!(result, Ok(false));
    }

    #[test]
    fn correct_footer_data() {
        const FOOTER: &str = "\x0d\x0a\
                              A PARSEC Production\x0d\x0a\
                              This is the end of the file!\x0d\x0a\
                              Das ist das Ende der Datei!\x0d\x0a\
                              C'est le fin du fichier!\x0d\x0a\x00";
        let result = verify_footer(FOOTER.as_bytes());
        assert_matches!(result, Ok(true));
    }
}
