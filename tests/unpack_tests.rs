use parsec_exe_unpacker::{unpack_exe, Options};

use common_failures::prelude::*;
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf}
};
use tempfile::tempdir;

// -------------------------------------------------------------------------------------------------

#[test]
fn autogen_output_filename() {
    let dir = tempdir().unwrap();

    let input_file = dir.path().join("XP00.EXE");
    fs::copy("tests/executables/BIFI2/XP00.EXE", &input_file).unwrap();

    let options = Options {
        input_file,
        output_file: None
    };

    unpack_exe(&options).unwrap();

    let expected_output_file = dir.path().join("XP00.unpacked.exe");
    assert!(expected_output_file.is_file());
}

// -------------------------------------------------------------------------------------------------

fn to_hex_string(bytes: impl Iterator<Item = u8>) -> String {
    let mut hex_string = String::with_capacity(bytes.size_hint().0 * 2);
    for byte in bytes {
        use std::fmt::Write;
        write!(hex_string, "{:02X}", byte);
    }
    hex_string
}

// -------------------------------------------------------------------------------------------------

fn hash_file(path: impl AsRef<Path>) -> Result<String> {
    let mut digest = Sha256::new();
    std::io::copy(&mut fs::File::open(path)?, &mut digest)?;
    Ok(to_hex_string(digest.result().into_iter()))
}

// -------------------------------------------------------------------------------------------------

fn test_unpack(path: impl Into<PathBuf>, expected_hash: &str) {
    let dir = tempdir().unwrap();
    let output_file = dir.path().join("out.exe");

    let options = Options {
        input_file: path.into(),
        output_file: Some(output_file.clone())
    };

    unpack_exe(&options).unwrap();

    assert_eq!(expected_hash, hash_file(&output_file).unwrap().as_str());
}

// See: https://stackoverflow.com/a/34666891
macro_rules! unpack_tests {
    ($($name:ident: $value:expr,)*) => {
    $(
        #[test]
        fn $name() {
            let (path, hash) = $value;
            test_unpack(path, hash);
        }
    )*
    }
}

unpack_tests! {
    bifi2_psmcfg4: ("tests/executables/BIFI2/PSMCFG4.EXE", "BBEC695AC4A6F013D1F5DBD63CC1CB30302159134306E2012DD5884394BAF2D7"),
    bifi2_xp00: ("tests/executables/BIFI2/XP00.EXE", "1B86692F83BBD065B8BCC0503BBE6180C0699A645E182C4554784B470382E4F0"),
    bifi2_xp01: ("tests/executables/BIFI2/XP01.EXE", "0A7B074E0E4DBFEF82D8379F931EAEB23B15ABADD68658C1F93BF26BE4FDEDED"),
    bstage_xp00: ("tests/executables/BSTAGE/XP00.EXE", "2A84B6B82F7A30203505FBCD474F7C29D53B0C9FE008C07A9CEECDC760442546"),
    capzins_xp00: ("tests/executables/CAPZINS/XP00.EXE", "898F57CBDF9DD7A925938217B1FBD7AA611A7D31833245AA3784E3A2DF24F197"),
    capzins_xp01: ("tests/executables/CAPZINS/XP01.EXE", "3D796EAE0AEAE3ABC5B67A70FE9CCBD4AE787E57B1878436865D7A80B866C4BF"),
    capzins_xp02: ("tests/executables/CAPZINS/XP02.EXE", "0D0CF629FC0EC9749AC10B3D3ECE7484ABD3AD838F38B9A4870F8DC12E5CD88E"),
    schatten_xp00: ("tests/executables/SCHATTEN/XP00.EXE", "1D9CD0A854F9DE36F4A8D2A3F5A184D6B0F053C2AFDED5239E41BD927E1F9F30"),
    schatten_xp01: ("tests/executables/SCHATTEN/XP01.EXE", "BC5AB47E21E7718BA214A256825CCFF5BAE9EAAC4AC865E093E49ADDE0335DE8"),
    schatten_xp02: ("tests/executables/SCHATTEN/XP02.EXE", "0D0CF629FC0EC9749AC10B3D3ECE7484ABD3AD838F38B9A4870F8DC12E5CD88E"),
    telekom_psmcfg3: ("tests/executables/TELEKOM2/PSMCFG3.EXE", "26D8E880B1685803DCEC0A0415C7AAE0EABCA08B00E7E05E82E3634A20521DF8"),
    telekom_xp00: ("tests/executables/TELEKOM2/XP00.EXE", "C82BBF75DBABB712BD50B3969F6DCF921BB405FE50B322ED550AB49CAB878CF8"),
    telekom_xp01: ("tests/executables/TELEKOM2/XP01.EXE", "7C102BD4C351ED085B3E0DA7065A104DCD2B659428C7EB0336E668F75348B70B"),
}
