mod dos_exe;
mod parsec_exe;
mod unpacker;

// -------------------------------------------------------------------------------------------------

use clap::{App, Arg};
use crate::dos_exe::SegmentOffsetPtr;
use failure::{bail, ResultExt};
use std::{
    fs::OpenOptions,
    io::{prelude::*, BufWriter},
    path::PathBuf
};

type Result<T> = failure::Fallible<T>;

// -------------------------------------------------------------------------------------------------

// TODO: 0x0011 does not work (SCHATTEN\XP01.EXE)! But why?

struct UnpackedExe {
    initial_stack_ptr: SegmentOffsetPtr,
    relocation_table: Vec<SegmentOffsetPtr>,
    executable_data: Vec<u8>
}

fn unpack_exe<R: Read>(mut reader: R) -> Result<UnpackedExe> {
    println!("Parsing executable header ...");
    let header_info =
        parsec_exe::parse_header(&mut reader).context("Failed to parse exe header.")?;

    println!("Reading executable data ...");
    let executable_data = {
        let mut data = vec![0u8; header_info.load_module_len];
        reader
            .read_exact(&mut data[..])
            .context("Failed to read exe data.")?;
        data
    };

    println!("Verifying footer ...");
    let is_footer_valid = parsec_exe::verify_footer(&mut reader)?;
    if !is_footer_valid {
        bail!("File does not contain a valid parsec footer.");
    }

    const BASE_SEGMENT0: u16 = 0x0010;
    const BASE_SEGMENT1: u16 = 0x0112;

    println!("Unpacking at base segment 0x{:04x} ...", BASE_SEGMENT0);
    let unpacked0 = unpacker::emulate_unpacker(&executable_data, BASE_SEGMENT0, &header_info)?;

    println!("Unpacking at base segment 0x{:04x} ...", BASE_SEGMENT1);
    let unpacked1 = unpacker::emulate_unpacker(&executable_data, BASE_SEGMENT1, &header_info)?;

    if unpacked0.initial_stack_ptr != unpacked1.initial_stack_ptr {
        bail!("Unpacking produced inconsistent stack pointers.");
    }

    println!("Extracting relocation table ...");
    let relocation_data = unpacker::extract_relocation_table(
        BASE_SEGMENT0,
        &unpacked0.data,
        BASE_SEGMENT1,
        &unpacked1.data
    )?;

    Ok(UnpackedExe {
        initial_stack_ptr: unpacked0.initial_stack_ptr,
        relocation_table: relocation_data.relocation_table,
        executable_data: relocation_data.restored_executable_data
    })
}

fn build_file_names(
    input_file_param: Option<&str>,
    output_file_param: Option<&str>
) -> (PathBuf, PathBuf) {
    let input_file = PathBuf::from(input_file_param.unwrap());
    let output_file = if let Some(output_file) = output_file_param {
        PathBuf::from(output_file)
    } else {
        let mut output_file = input_file.clone();
        output_file.set_extension("unpacked.exe");
        output_file
    };

    (input_file, output_file)
}

fn run() -> Result<()> {
    let matches = App::new(env!("CARGO_PKG_NAME"))
        .author(env!("CARGO_PKG_AUTHORS"))
        .version(env!("CARGO_PKG_VERSION"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .arg(Arg::with_name("INPUT_FILE")
            .help("The file to be unpacked.")
            .index(1)
            .required(true))
        .arg(Arg::with_name("OUTPUT_FILE")
            .help("The output file to be written. If this is not specified the input filename with the extension '.unpacked.exe' is used.")
            .index(2))
        .get_matches();

    println!(concat!(
        env!("CARGO_PKG_NAME"),
        " ",
        env!("CARGO_PKG_VERSION")
    ));
    println!(env!("CARGO_PKG_AUTHORS"));
    println!();

    let (input_file, output_file) = build_file_names(
        matches.value_of("INPUT_FILE"),
        matches.value_of("OUTPUT_FILE")
    );

    let file = OpenOptions::new()
        .read(true)
        .open(&input_file)
        .with_context(|_| format!("Failed to open '{}' for reading.", input_file.display()))?;

    let unpacked_exe = unpack_exe(file)
        .with_context(|_| format!("Failed to unpack '{}'", input_file.display()))?;

    println!("Writing '{}' ...", output_file.display());

    let file = BufWriter::new(
        OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&output_file)
            .with_context(|_| format!("Failed to open '{}' for writing.", output_file.display()))?
    );

    dos_exe::write_executable(
        file,
        unpacked_exe.initial_stack_ptr,
        &unpacked_exe.relocation_table,
        &unpacked_exe.executable_data
    ).context("Failed to write unpacked executable.")?;

    Ok(())
}

fn main() {
    if let Err(e) = run() {
        failure_tools::print_causes(e, std::io::stderr());
        std::process::exit(1);
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn both_file_names_provided() {
        let (input_file, output_file) = build_file_names(
            Some(r"..\dir\input_file.exe"),
            Some(r"C:\dir\output_file.exe")
        );
        assert_eq!(PathBuf::from(r"..\dir\input_file.exe"), input_file);
        assert_eq!(PathBuf::from(r"C:\dir\output_file.exe"), output_file);
    }

    #[test]
    fn output_file_name_created() {
        let (input_file, output_file) = build_file_names(Some(r"..\dir\input_file.exe"), None);
        assert_eq!(PathBuf::from(r"..\dir\input_file.exe"), input_file);
        assert_eq!(
            PathBuf::from(r"..\dir\input_file.unpacked.exe"),
            output_file
        );
    }
}
