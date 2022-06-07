use parsec_exe_unpacker::{unpack_exe, Options};

use clap::{Arg, Command};
use eyre::Result;

fn get_options() -> Options {
    let matches = Command::new(env!("CARGO_PKG_NAME"))
        .author(env!("CARGO_PKG_AUTHORS"))
        .version(env!("CARGO_PKG_VERSION"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .arg(Arg::new("INPUT_FILE")
            .help("The file to be unpacked.")
            .index(1)
            .required(true))
        .arg(Arg::new("OUTPUT_FILE")
            .help("The output file to be written. If this is not specified the input filename with the extension '.unpacked.exe' is used.")
            .index(2))
        .get_matches();

    Options {
        input_file: matches.value_of("INPUT_FILE").unwrap().into(),
        output_file: matches.value_of("OUTPUT_FILE").map(|s| s.into()),
    }
}

fn main() -> Result<()> {
    unpack_exe(&get_options())
}
