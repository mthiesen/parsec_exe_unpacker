use byteorder::{LittleEndian, WriteBytesExt};
use crate::Result;
use failure::ResultExt;
use std::{fmt, io::Write, mem::size_of};

// -------------------------------------------------------------------------------------------------

pub const MZ_HEADER_SIGNATURE: u16 = 0x5a4d;
pub const PARAGRAPH_SIZE: usize = 16;
pub const SEGMENT_SIZE: usize = 16;
pub const PAGE_SIZE: usize = 512;

// -------------------------------------------------------------------------------------------------

#[derive(Debug)]
pub struct Info {
    pub load_module_len: usize,
    pub total_alloc_len: usize,
    pub initial_stack_ptr: SegmentOffsetPtr,
    pub entry_point: SegmentOffsetPtr
}

#[derive(Debug, PartialEq, Copy, Clone)]
pub struct SegmentOffsetPtr {
    pub segment: u16,
    pub offset: u16
}

impl SegmentOffsetPtr {
    pub fn new(segment: u16, offset: u16) -> SegmentOffsetPtr {
        SegmentOffsetPtr { segment, offset }
    }

    pub fn to_linear(self) -> usize {
        self.segment as usize * SEGMENT_SIZE + self.offset as usize
    }
}

impl fmt::Display for SegmentOffsetPtr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04x}:{:04x}", self.segment, self.offset)
    }
}

pub fn write_executable<W: Write>(
    mut writer: W,
    initial_stack_ptr: SegmentOffsetPtr,
    relocation_table: &[SegmentOffsetPtr],
    executable_data: &[u8]
) -> Result<()> {
    const BASE_HEADER_PARAGRAPHS: usize = 2;
    let header_paragraphs = {
        let reloc_tab_bytes = relocation_table.len() * size_of::<u16>() * 2;
        let reloc_tab_paragraphs = (reloc_tab_bytes + PARAGRAPH_SIZE - 1) / PARAGRAPH_SIZE;

        let total_paragraphs = BASE_HEADER_PARAGRAPHS + reloc_tab_paragraphs;

        // Header size has to be an even number of paragraphs.
        if (total_paragraphs & 1) != 0 {
            total_paragraphs + 1
        } else {
            total_paragraphs
        }
    };

    let file_pages = {
        let unpadded_bytes = header_paragraphs * PARAGRAPH_SIZE + executable_data.len();
        (unpadded_bytes + PAGE_SIZE - 1) / PAGE_SIZE
    };

    let mut header_bytes_written = 0;
    {
        let mut write_u16 = |v: u16| -> Result<()> {
            writer
                .write_u16::<LittleEndian>(v)
                .context("Failed to write executable header.")?;
            header_bytes_written += size_of::<u16>();
            Ok(())
        };

        write_u16(MZ_HEADER_SIGNATURE)?;

        write_u16(0)?;
        write_u16((file_pages + 1) as u16)?;

        write_u16(relocation_table.len() as u16)?;

        write_u16(header_paragraphs as u16)?;

        write_u16(0)?;
        write_u16(0xffff)?;

        write_u16(initial_stack_ptr.segment)?;
        write_u16(initial_stack_ptr.offset)?;

        write_u16(0)?;
        write_u16(0)?;
        write_u16(0)?;

        write_u16((BASE_HEADER_PARAGRAPHS * PARAGRAPH_SIZE) as u16)?;

        write_u16(0)?;
        write_u16(0)?;
        write_u16(0)?;

        for relocation_entry in relocation_table {
            write_u16(relocation_entry.offset)?;
            write_u16(relocation_entry.segment)?;
        }
    }

    assert!(header_paragraphs * PARAGRAPH_SIZE >= header_bytes_written);
    let padding_size = header_paragraphs * PARAGRAPH_SIZE - header_bytes_written;
    if padding_size > 0 {
        let padding = [0u8; PARAGRAPH_SIZE * 2];
        writer
            .write_all(&padding[0..padding_size])
            .context("Failed to write executable header.")?;
    }

    writer
        .write_all(executable_data)
        .context("Failed to write executable data.")?;

    let total_bytes_written = header_paragraphs * PARAGRAPH_SIZE + executable_data.len();
    assert!(file_pages * PAGE_SIZE >= total_bytes_written);
    let padding_size = file_pages * PAGE_SIZE - total_bytes_written;
    if padding_size > 0 {
        let padding = [0u8; PAGE_SIZE];
        writer
            .write_all(&padding[0..padding_size])
            .context("Failed to write executable data.")?;
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn segment_offset_ptr_to_linear() {
        assert_eq!(0x12345, SegmentOffsetPtr::new(0x1234, 0x0005).to_linear());
        assert_eq!(0x179b8, SegmentOffsetPtr::new(0x1234, 0x5678).to_linear());
    }

    #[test]
    fn segment_offset_ptr_display() {
        assert_eq!(
            "1234:5678",
            format!("{}", SegmentOffsetPtr::new(0x1234, 0x5678))
        );
    }
}
