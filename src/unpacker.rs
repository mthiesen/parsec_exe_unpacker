use crate::dos_exe::{Info, SegmentOffsetPtr, SEGMENT_SIZE};
use byteorder::{ByteOrder, LittleEndian};
use eyre::bail;
use eyre::eyre;
use eyre::Result;
use eyre::WrapErr;
use std::result::Result as StdResult;
use unicorn_engine::{
    unicorn_const::{uc_error, Arch, Mode, Permission},
    RegisterX86, Unicorn,
};

// -------------------------------------------------------------------------------------------------

const MAX_NUMBER_OF_INSTRUCTIONS: usize = 100_000_000;

// -------------------------------------------------------------------------------------------------

trait UnicornResultExt<T> {
    fn chain_err_msg(self, msg: &str) -> Result<T>;
}

fn unicorn_error_msg(err: uc_error) -> String {
    let err_str = match err {
        uc_error::OK => "OK",
        uc_error::NOMEM => "NOMEM",
        uc_error::ARCH => "ARCH",
        uc_error::HANDLE => "HANDLE",
        uc_error::MODE => "MODE",
        uc_error::VERSION => "VERSION",
        uc_error::READ_UNMAPPED => "READ_UNMAPPED",
        uc_error::WRITE_UNMAPPED => "WRITE__UNMAPPED",
        uc_error::FETCH_UNMAPPED => "FETCH_UNMAPPED",
        uc_error::HOOK => "HOOK",
        uc_error::INSN_INVALID => "INSN_INVALID",
        uc_error::MAP => "MAP",
        uc_error::WRITE_PROT => "WRITE_PROT",
        uc_error::READ_PROT => "READ_PROT",
        uc_error::FETCH_PROT => "FETCH_PROT",
        uc_error::ARG => "ARG",
        uc_error::READ_UNALIGNED => "READ_UNALIGNED",
        uc_error::WRITE_UNALIGNED => "WRITE_UNALIGNED",
        uc_error::FETCH_UNALIGNED => "FETCH_UNALIGNED",
        uc_error::HOOK_EXIST => "HOOK_EXIST",
        uc_error::RESOURCE => "RESOURCE",
        uc_error::EXCEPTION => "EXCEPTION",
    };

    format!("Unicorn error code {err_str}")
}

impl<T> UnicornResultExt<T> for StdResult<T, uc_error> {
    fn chain_err_msg(self, msg: &str) -> Result<T> {
        match self {
            Err(err) => Err(eyre!(unicorn_error_msg(err))).wrap_err(msg.to_owned())?,
            Ok(ok) => Ok(ok),
        }
    }
}

pub struct UnpackedExecutable {
    pub data: Vec<u8>,
    pub initial_stack_ptr: SegmentOffsetPtr,
}

pub fn emulate_unpacker(
    executable_data: &[u8],
    base_segment: u16,
    header_info: &Info,
) -> Result<UnpackedExecutable> {
    let mut emulator = Unicorn::new(Arch::X86, Mode::MODE_16)
        .chain_err_msg("Failed to create 16-bit x86 Unicorn emulator.")?;
    emulator
        .mem_map(0, 0xa0000, Permission::ALL)
        .chain_err_msg("Failed to map emulator memory.")?;

    assert!(base_segment >= 0x10);
    let psp_segment = base_segment - 0x10;
    let load_location = u64::from(base_segment) * SEGMENT_SIZE as u64;
    emulator
        .mem_write(load_location, executable_data)
        .chain_err_msg("Failed to write executable data to emulator memory.")?;

    // I did not manage to set the initial instruction pointer for the call to emu_start()
    // correctly. As a work-around I assemble a jump to the desired location at address 0 and start
    // the emulation there.
    let trampoline_code = {
        let mut buffer = [0xea_u8, 0, 0, 0, 0];
        let initial_cs = header_info.entry_point.segment + base_segment;
        LittleEndian::write_u16(&mut buffer[0x01..], header_info.entry_point.offset);
        LittleEndian::write_u16(&mut buffer[0x03..], initial_cs);
        buffer
    };
    emulator
        .mem_write(0, &trampoline_code[..])
        .chain_err_msg("Failed to write trampoline code to emulator memory.")?;

    let initial_ss = u64::from(header_info.initial_stack_ptr.segment + base_segment);
    emulator
        .reg_write(RegisterX86::SS, initial_ss)
        .chain_err_msg("Failed to set emulators SS register.")?;
    emulator
        .reg_write(
            RegisterX86::SP,
            u64::from(header_info.initial_stack_ptr.offset),
        )
        .chain_err_msg("Failed to set emulators SP register.")?;

    emulator
        .reg_write(RegisterX86::ES, u64::from(psp_segment))
        .chain_err_msg("Failed to set emulators ES register.")?;
    emulator
        .reg_write(RegisterX86::DS, u64::from(psp_segment))
        .chain_err_msg("Failed to set emulators DS register.")?;

    emulator
        .emu_start(0, load_location, 0, MAX_NUMBER_OF_INSTRUCTIONS)
        .chain_err_msg(
            "Code emulation failed. Execution did not reach the original entry point.",
        )?;

    let cs = emulator
        .reg_read(RegisterX86::CS)
        .chain_err_msg("Failed to read emulators CS register.")?;
    let ip = emulator
        .reg_read(RegisterX86::IP)
        .chain_err_msg("Failed to read emulators IP register.")?;
    if cs != u64::from(base_segment) || ip != 0 {
        bail!("Code emulation failed. Execution did not reach the original entry point.");
    }

    let ss = {
        let ss = emulator
            .reg_read(RegisterX86::SS)
            .chain_err_msg("Failed to read emulators SS register.")?;
        if ss < u64::from(base_segment) {
            bail!("Invalid stack segment after code emulation.");
        }
        ss - u64::from(base_segment)
    };
    if ss > u64::from(std::u16::MAX) {
        bail!("Value in SS register after code emulation is too big.");
    }

    let sp = emulator
        .reg_read(RegisterX86::SP)
        .chain_err_msg("Failed to read emulators SP register.")?;

    if sp > u64::from(std::u16::MAX) {
        bail!("Value in SP register after code emulation is too big.");
    }

    let mut unpacked_data = vec![0u8; header_info.total_alloc_len];
    emulator
        .mem_read(load_location, &mut unpacked_data)
        .chain_err_msg("Failed to read unpacked executable data from emulator.")?;

    Ok(UnpackedExecutable {
        data: unpacked_data,
        initial_stack_ptr: SegmentOffsetPtr {
            segment: ss as u16,
            offset: sp as u16,
        },
    })
}

pub struct RelocationData {
    pub restored_executable_data: Vec<u8>,
    pub relocation_table: Vec<SegmentOffsetPtr>,
}

pub fn extract_relocation_table(
    base_segment0: u16,
    unpacked_data0: &[u8],
    base_segment1: u16,
    unpacked_data1: &[u8],
) -> Result<RelocationData> {
    let relocation_table =
        build_relocation_table(base_segment0, unpacked_data0, base_segment1, unpacked_data1);

    let unrelocated_data0 = unrelocate(base_segment0, unpacked_data0, &relocation_table);
    let unrelocated_data1 = unrelocate(base_segment1, unpacked_data1, &relocation_table);

    if unrelocated_data0 != unrelocated_data1 {
        bail!("Failed to restore executable data to unrelocated state.");
    }

    Ok(RelocationData {
        restored_executable_data: unrelocated_data0,
        relocation_table,
    })
}

fn build_relocation_table(
    base_segment0: u16,
    unpacked_data0: &[u8],
    base_segment1: u16,
    unpacked_data1: &[u8],
) -> Vec<SegmentOffsetPtr> {
    assert!(base_segment0 < base_segment1);
    assert!(unpacked_data0.len() == unpacked_data1.len());

    let base_segment_diff = base_segment1 - base_segment0;

    unpacked_data0
        .windows(2)
        .zip(unpacked_data1.windows(2))
        .map(|(a, b)| LittleEndian::read_u16(b).wrapping_sub(LittleEndian::read_u16(a)))
        .enumerate()
        .filter(|&(_, diff)| diff == base_segment_diff)
        .map(|(index, _)| SegmentOffsetPtr {
            segment: (index / SEGMENT_SIZE) as u16,
            offset: (index % SEGMENT_SIZE) as u16,
        })
        .collect()
}

fn unrelocate(base_segment: u16, data: &[u8], relocation_table: &[SegmentOffsetPtr]) -> Vec<u8> {
    let mut result = data.to_vec();
    for relocation_entry in relocation_table {
        let index = relocation_entry.to_linear();
        let relocated_value = &mut result[index..index + 2];
        let unrelocated_value = LittleEndian::read_u16(relocated_value).wrapping_sub(base_segment);
        LittleEndian::write_u16(relocated_value, unrelocated_value);
    }
    result
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn no_relocation_entries_found_if_data_identical() {
        const UNPACKED_DATA0: [u8; 32] = [
            0x9A, 0x82, 0x41, 0x8C, 0x3D, 0xD0, 0x0D, 0x84, 0x66, 0xD8, 0xFC, 0x32, 0x81, 0x90,
            0xD3, 0xAE, 0xE9, 0xED, 0xC0, 0xB3, 0xB4, 0x71, 0xD7, 0x10, 0x70, 0x6A, 0xF8, 0x77,
            0x91, 0x53, 0xD8, 0x22,
        ];

        let relocation_table =
            build_relocation_table(0x0010, &UNPACKED_DATA0, 0x0112, &UNPACKED_DATA0);

        assert!(relocation_table.is_empty());
    }

    #[test]
    fn finds_all_relocation_entries() {
        const UNPACKED_DATA0: [u8; 32] = [
            0x9A, 0x82, 0x41, 0x8C, 0x3D, 0xE0, 0x0D, 0x94, 0x66, 0xD8, 0xFC, 0x32, 0x81, 0x90,
            0xD3, 0xAE, 0xE9, 0xED, 0xC0, 0xB3, 0xB4, 0x71, 0xE7, 0x10, 0x70, 0x6A, 0xF8, 0x87,
            0x91, 0x53, 0xD8, 0x22,
        ];

        const UNPACKED_DATA1: [u8; 32] = [
            0x9A, 0x82, 0x41, 0x8C, 0x3D, 0xE2, 0x0E, 0x96, 0x67, 0xD8, 0xFC, 0x32, 0x81, 0x90,
            0xD3, 0xAE, 0xE9, 0xED, 0xC0, 0xB3, 0xB4, 0x71, 0xE9, 0x11, 0x70, 0x6A, 0xF8, 0x89,
            0x92, 0x53, 0xD8, 0x22,
        ];

        let relocation_table =
            build_relocation_table(0x0010, &UNPACKED_DATA0, 0x0112, &UNPACKED_DATA1);

        let linear_relocation_table: Vec<usize> =
            relocation_table.iter().map(|e| e.to_linear()).collect();

        assert_eq!(vec![5, 7, 22, 27], linear_relocation_table);
    }

    #[test]
    fn invalid_differences_dont_produce_relocation_entries() {
        const UNPACKED_DATA0: [u8; 32] = [
            0x9A, 0x82, 0x41, 0x8C, 0x3D, 0xE0, 0x0D, 0x94, 0x66, 0xD8, 0xFC, 0x32, 0x81, 0x90,
            0xD3, 0xAE, 0xE9, 0xED, 0xC0, 0xB3, 0xB4, 0x71, 0xE7, 0x10, 0x70, 0x6A, 0xF8, 0x87,
            0x91, 0x53, 0xD8, 0x22,
        ];

        const UNPACKED_DATA1: [u8; 32] = [
            0x9A, 0x82, 0x41, 0x8C, 0x3D, 0xE2, 0x0E, 0x96, 0x67, 0xD8, 0xFC, 0x32, 0x81, 0x90,
            0xD3, 0xAE, 0xE9, 0xED, 0xC0, 0xB3, 0xB4, 0x71, 0xE9, 0x11, 0x70, 0x6A, 0xF8, 0x89,
            0x92, 0x53, 0xD8, 0x22,
        ];

        let relocation_table =
            build_relocation_table(0x0010, &UNPACKED_DATA0, 0x0113, &UNPACKED_DATA1);

        assert!(relocation_table.is_empty());
    }

    #[test]
    fn unrelocation_test() {
        const UNPACKED_DATA: [u8; 32] = [
            0x9A, 0x82, 0x41, 0x8C, 0x3D, 0xE0, 0x0D, 0x94, 0x66, 0xD8, 0xFC, 0x32, 0x81, 0x90,
            0xD3, 0xAE, 0xE9, 0xED, 0xC0, 0xB3, 0xB4, 0x71, 0xE7, 0x10, 0x70, 0x6A, 0xF8, 0x87,
            0x91, 0x53, 0xD8, 0x22,
        ];

        let relocation_table = vec![
            SegmentOffsetPtr::new(0, 5),
            SegmentOffsetPtr::new(0, 7),
            SegmentOffsetPtr::new(1, 6),
            SegmentOffsetPtr::new(1, 11),
        ];

        let unrelocated_data = unrelocate(0x0010, &UNPACKED_DATA, &relocation_table);

        const EXPECTED_UNRELOCATED_DATA: [u8; 32] = [
            0x9A, 0x82, 0x41, 0x8C, 0x3D, 0xD0, 0x0D, 0x84, 0x66, 0xD8, 0xFC, 0x32, 0x81, 0x90,
            0xD3, 0xAE, 0xE9, 0xED, 0xC0, 0xB3, 0xB4, 0x71, 0xD7, 0x10, 0x70, 0x6A, 0xF8, 0x77,
            0x91, 0x53, 0xD8, 0x22,
        ];

        assert_eq!(&EXPECTED_UNRELOCATED_DATA, unrelocated_data.as_slice());
    }
}
