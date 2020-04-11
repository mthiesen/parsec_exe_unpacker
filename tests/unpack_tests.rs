use parsec_exe_unpacker::{unpack_exe, Options};

use common_failures::prelude::*;
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
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
        output_file: None,
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
        write!(hex_string, "{:02X}", byte).expect("writing to a string should not fail");
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
        output_file: Some(output_file.clone()),
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
    bifi2_psmcfg4: ("tests/executables/BIFI2/PSMCFG4.EXE", "CDB9BFDA626D7687FA2C851EAAD36CA0DAC18BA6D4E34CCE72CBD58275CF6F04"),
    bifi2_xp00: ("tests/executables/BIFI2/XP00.EXE", "C51348B01A88CF91F8C1D524993DE2714F41A71C758417854006531E704A09A7"),
    bifi2_xp01: ("tests/executables/BIFI2/XP01.EXE", "E9850964870A61D74EE33406F9B4ED1F445DD5A6B56881080040979041DD30F5"),
    bstage_xp00: ("tests/executables/BSTAGE/XP00.EXE", "B6698C0B834D738CAB4220BF7EF3D4C37720DEE1233DC543929A3D40D238BF38"),
    capzins_xp00: ("tests/executables/CAPZINS/XP00.EXE", "1C11F1CA7DD711ABE1C3C1E792572F592B2DC06BEB90CAD7C771DB9F3793DC46"),
    capzins_xp01: ("tests/executables/CAPZINS/XP01.EXE", "E16906FFE735F16B21E0EC34974C7572541AA10290F6143F38E499D0E83A5543"),
    capzins_xp02: ("tests/executables/CAPZINS/XP02.EXE", "18779E6AB46F653981A623BF38310E447213E5A61B727BE206699BB3F15AAACC"),
    schatten_xp00: ("tests/executables/SCHATTEN/XP00.EXE", "0CF76D7BF2B090B420D1DED91128065B667B948C23CFEF3A53AC7150F9EE77EA"),
    schatten_xp01: ("tests/executables/SCHATTEN/XP01.EXE", "0AF97CAA32B92C3EAF05100A587442187D79EE69AECA28BFCB5DFB1A155B4819"),
    schatten_xp02: ("tests/executables/SCHATTEN/XP02.EXE", "18779E6AB46F653981A623BF38310E447213E5A61B727BE206699BB3F15AAACC"),
    telekom_psmcfg3: ("tests/executables/TELEKOM2/PSMCFG3.EXE", "DC0FBB7950A57BBD4FA7A1E6898B39B43E26D2C07A58A65917BAE0FBA24F59DA"),
    telekom_xp00: ("tests/executables/TELEKOM2/XP00.EXE", "83063DD5D21777A1456E9AD8379911AD184C4616B4442A09EC191F689F6BFA82"),
    telekom_xp01: ("tests/executables/TELEKOM2/XP01.EXE", "8109FBE30F0E7EC79B88354B5EEF186ABE82D49E887F4F9D803EB93A5958910D"),
}
