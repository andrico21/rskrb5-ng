// Generated from the MIT krb5 1.22.2 tests and host MIT libk5crypto 1.22.1 (see the evidence log); do not edit.

/// A `t_cf2.in` row: both keys come from `string_to_key(pass, pass)`.
#[derive(Clone, Copy, Debug)]
struct CfS2kVector {
    /// Etype ID.
    etype: i32,
    /// First passphrase, also its salt.
    pass1: &'static str,
    /// Second passphrase, also its salt.
    pass2: &'static str,
    /// First pepper.
    pepper1: &'static str,
    /// Second pepper.
    pepper2: &'static str,
    /// Expected key, hex.
    expected: &'static str,
}

/// A `krb5_c_fx_cf2_simple` row with explicit keys.
#[derive(Clone, Copy, Debug)]
struct CfVector {
    /// Etype ID.
    etype: i32,
    /// First key, hex.
    key1: &'static str,
    /// Second key, hex.
    key2: &'static str,
    /// First pepper.
    pepper1: &'static str,
    /// Second pepper.
    pepper2: &'static str,
    /// Expected key, hex.
    expected: &'static str,
}

/// A `src/tests/gssapi/t_prf.c` row.
#[derive(Clone, Copy, Debug)]
struct GssVector {
    /// Etype ID.
    etype: i32,
    /// Subkey, hex.
    key1: &'static str,
    /// Expected 44 bytes for `key1` and an empty input, hex.
    out1: &'static str,
    /// Acceptor subkey, hex.
    key2: &'static str,
    /// Expected 44 bytes for `key2` and the 61-byte input string, hex.
    out2: &'static str,
}

/// A `krb5_c_prfplus` row.
#[derive(Clone, Copy, Debug)]
struct PlusVector {
    /// Etype ID.
    etype: i32,
    /// Key, hex.
    key: &'static str,
    /// PRF+ input, hex.
    input: &'static str,
    /// Requested output length.
    len: usize,
    /// Expected output, hex.
    expected: &'static str,
}

/// A `src/lib/crypto/crypto_tests/t_prf.c` row.
#[derive(Clone, Copy, Debug)]
struct RawPrfVector {
    /// Etype ID.
    etype: i32,
    /// Key, hex.
    key: &'static str,
    /// PRF input, hex.
    input: &'static str,
    /// Expected PRF output, hex.
    expected: &'static str,
}

/// `src/tests/gssapi/t_prf.c` (krb5-1.22.2-final): out1 = PARTIAL key (subkey) with empty input, out2 = FULL key (acceptor subkey) with the 61-byte string; 44 bytes each.
const GSS: &[GssVector] = &[

    GssVector { etype: 16, key1: "70378a19cd64134580c27c0115d6b34a1cf2feecef9886a2", out1: "9f8d127c520bb826bff3e0fe5ef352389c17e0c073d9ac4a333d644d21ba3ef24f4a886d143f85ac9f6377fb", key2: "3452a167df1094ba1089e0a20e9e51abef1525922558b69e", out2: "6bf24fabc858f8dd9752e4fcd331bb831f238b5be1904eea42e38f7a60c588f075c5c96a67e7f8b7bd0aecf4" },
    GssVector { etype: 23, key1: "3bb3ae288c12b3b9d06b208a4151b3b6", out1: "9aea11a3bcf3c53f1f91f5a0ba2132e2501adf5f3c283c8a983ab88757ce865a22132d6100ead63e9e291afa", key2: "6db7b33a01bd2b72f7655cb7b3d5fa0b", out2: "cda9a544869fc84873b692663a82afda101c8611498ba46138b01e927c9b95eec953b562807434037837dddf" },
    GssVector { etype: 17, key1: "6c742096eb896230312b73972fa28b5d", out1: "94208d982fc1bb7778128bdd77904420b45c9da699f3117bce66e39602128ef0296611a6d191a5828530f20f", key2: "fa61138c109d834a477d24c7311be6da", out2: "0faedf0f842cc834fee750487e1b622739286b975fe5b7f45ab053143c75ca0df5d3d4bbb80f6a616c7c9027" },
    GssVector { etype: 18, key1: "08fcdafd5832611b73ba7b497febff8c954b4b58031cad9b977c3b8c25192fd6", out1: "e627efc14ef5b6d629f830c7109dea0d3d7d36e8cd57a1f301c5452494a1928f05affbee3360232209d3be0d", key2: "f5b68b7823d8944f33f41541b4e4d38c9b2934f8d16334a796645b066152b4be", out2: "112f2b2d878590653ccc7de278e9f0aa46fa5a380b6259f774cb7c134fcd37f61a50fd0d9f89bf8fe1a6b593" },
    GssVector { etype: 19, key1: "089bca48b105ea6ea77ca5d2f39dc5e7", out1: "ed1736209b7c59c9f6a3ae8ccc8a7c97adfdd11688adf304f2f74252cbacd311a2d9253211fda49745ce4f62", key2: "3705d96080c17728a0e800eab6e0d23c", out2: "2bb41b183d76d8d5b30cbb049a7efe9f350efa058dc2c4d868308d354a7b199be6fd1f22b53c038bc6036581" },
    GssVector { etype: 20, key1: "45bd806dbf6a833a9cffc1c94589a222367a79bc21c413718906e9f578a78467", out1: "1c613ae8b77a3b4d783f3dce6c9178fc025e87f48a44784a69cb5fc697fe266a6141905067ef78566d309085", key2: "6d404d37faf79f9df0d33568d320669800eb4836472ea8a026d16b7182460c52", out2: "d15944b0a44508d1e61213f6455f292a02298f870c01a3f74ad0345a4a6651ebe101976e933f32d44f0b5947" },

];

/// `src/lib/crypto/crypto_tests/t_prf.c` (krb5-1.22.2-final), raw `krb5_c_prf`.
const RAW: &[RawPrfVector] = &[

    RawPrfVector { etype: 17, key: "ae272e7cdec86ac5138cdb196d8e297d", input: "0161", expected: "77b39a37a868920f2a51f9dd150c5717" },
    RawPrfVector { etype: 17, key: "67ab1cfef35e4c27ffdeac60385a3e9c", input: "0162", expected: "e06c0dd31ff02091994f2ef5178bfe3d" },
    RawPrfVector { etype: 18, key: "c01f157211f7b77eaaf457c3e156690127ee127d810ba6392e97baa243eb0616", input: "0161", expected: "b2628c788e2e9c4a9bb4644678c29f2f" },
    RawPrfVector { etype: 18, key: "c01f157211f7b77eaaf457c3e156690127ee127d810ba6392e97baa243eb0616", input: "0261", expected: "b406373350cee8a6126f4a9b65a0cd21" },
    RawPrfVector { etype: 18, key: "9d520d2d980aa7cb6b693682b62da258b333867951642ce647ae62b1e5e0b5e9", input: "0162", expected: "ff0e289ea756c0559a0e911856961a49" },
    RawPrfVector { etype: 18, key: "9d520d2d980aa7cb6b693682b62da258b333867951642ce647ae62b1e5e0b5e9", input: "0262", expected: "0d674dd0f9a6806525a4d92e828bd15a" },
    RawPrfVector { etype: 19, key: "3705d96080c17728a0e800eab6e0d23c", input: "74657374", expected: "9d188616f63852fe86915bb840b4a886ff3e6bb0f819b49b893393d393854295" },
    RawPrfVector { etype: 20, key: "6d404d37faf79f9df0d33568d320669800eb4836472ea8a026d16b7182460c52", input: "74657374", expected: "9801f69a368c2bf675e59521e177d9a07f67efe1cfde8d3c8d6f6a0256e3b17db3c1b62ad1b8553360d17367eb1514d2" },

];

/// `src/lib/crypto/crypto_tests/t_cf2.{in,expected}` (krb5-1.22.2-final): both keys are `string_to_key(keyN, salt = keyN)`, peppers `a` and `b`.
const CF2_MIT: &[CfS2kVector] = &[

    CfS2kVector { etype: 17, pass1: "key1", pass2: "key2", pepper1: "a", pepper2: "b", expected: "97df97e4b798b29eb31ed7280287a92a" },
    CfS2kVector { etype: 18, pass1: "key1", pass2: "key2", pepper1: "a", pepper2: "b", expected: "4d6ca4e629785c1f01baf55e2e548566b9617ae3a96868c337cb93b5e72b1c7b" },
    CfS2kVector { etype: 16, pass1: "key1", pass2: "key2", pepper1: "a", pepper2: "b", expected: "e58f9eb643862c13ad38e529313462a7f73e62834fe54a01" },
    CfS2kVector { etype: 23, pass1: "key1", pass2: "key2", pepper1: "a", pepper2: "b", expected: "24d7f6b6bae4e5c00d2082c5ebab3672" },
    CfS2kVector { etype: 19, pass1: "key1", pass2: "key2", pepper1: "a", pepper2: "b", expected: "edd02a39d2dbde31611c16e610be062c" },
    CfS2kVector { etype: 20, pass1: "key1", pass2: "key2", pepper1: "a", pepper2: "b", expected: "67f6ea530aea85a37dcbb23349ea52dcc61ca8493ff557252327fd8304341584" },

];

/// `krb5_c_prfplus` of host libk5crypto 1.22.1 (`gen_mit_vectors.py`).
const PLUS: &[PlusVector] = &[

    PlusVector { etype: 17, key: "3a825ddb45e6a293480ebec8b88673bd", input: "696e707574", len: 1, expected: "8d" },
    PlusVector { etype: 17, key: "3a825ddb45e6a293480ebec8b88673bd", input: "696e707574", len: 16, expected: "8d98051b46f95074fdfa80440c4dd95c" },
    PlusVector { etype: 17, key: "3a825ddb45e6a293480ebec8b88673bd", input: "66697874757265207072662b20696e707574", len: 35, expected: "9c8c79ef19d8cb82a2c68b979399e60e798f2c7a43c853a674b808f29931867c9594c4" },
    PlusVector { etype: 17, key: "3a825ddb45e6a293480ebec8b88673bd", input: "", len: 5, expected: "49ebbe915d" },
    PlusVector { etype: 17, key: "3a825ddb45e6a293480ebec8b88673bd", input: "78787878787878787878787878787878787878787878787878787878787878787878787878787878", len: 100, expected: "a65acafa648ee2a0a5d380c41fd23b48de2894e895e381e97d887093e836a5e095a545d8b26521ea078bd8cc4c0058c571da48521a9f2269febeb9c59e8b86f101016de8633999ee847fbf2182dfe4b5809a005883448c36a66f33b6481ec151ac3ede47" },
    PlusVector { etype: 18, key: "4d1481a5e25c5ad520b328ac1a1a67204e33d6005ad04b1c1b3d415f76e41eff", input: "696e707574", len: 1, expected: "0f" },
    PlusVector { etype: 18, key: "4d1481a5e25c5ad520b328ac1a1a67204e33d6005ad04b1c1b3d415f76e41eff", input: "696e707574", len: 16, expected: "0fedf39705d73589bd2fb67879783b4f" },
    PlusVector { etype: 18, key: "4d1481a5e25c5ad520b328ac1a1a67204e33d6005ad04b1c1b3d415f76e41eff", input: "66697874757265207072662b20696e707574", len: 35, expected: "31742dbcc2a4b487d5658145ad32d673879f82c91f98edd5452734f5576c213ba7659c" },
    PlusVector { etype: 18, key: "4d1481a5e25c5ad520b328ac1a1a67204e33d6005ad04b1c1b3d415f76e41eff", input: "", len: 5, expected: "54327a36ac" },
    PlusVector { etype: 18, key: "4d1481a5e25c5ad520b328ac1a1a67204e33d6005ad04b1c1b3d415f76e41eff", input: "78787878787878787878787878787878787878787878787878787878787878787878787878787878", len: 100, expected: "639df52c8dc98382f6093200d9c7fc53811f13c7f606e6a7b5807379ab299bb8b6e6c7f4a2c3f8bb39e2ae2cb675c729da64cc7c1cc6550c0fd1b4e5bec47b0e4bfb54a6d32c0ae5f2beb20668efaf9a9cd811a74cb71f3a9c99bbc79918304e40989a17" },
    PlusVector { etype: 23, key: "16b8ae6ef569f1f4fe2d08b81e032abc", input: "696e707574", len: 1, expected: "64" },
    PlusVector { etype: 23, key: "16b8ae6ef569f1f4fe2d08b81e032abc", input: "696e707574", len: 20, expected: "6432e6a6578ed113a0a83a38c186ded1223cf839" },
    PlusVector { etype: 23, key: "16b8ae6ef569f1f4fe2d08b81e032abc", input: "66697874757265207072662b20696e707574", len: 43, expected: "9f7b277e6d727f9ea93e188a98c6b11052a4b5021c6be04ce2547884c6310148a6e06e274b5ecdbe0f6be4" },
    PlusVector { etype: 23, key: "16b8ae6ef569f1f4fe2d08b81e032abc", input: "", len: 5, expected: "8a569479ba" },
    PlusVector { etype: 23, key: "16b8ae6ef569f1f4fe2d08b81e032abc", input: "78787878787878787878787878787878787878787878787878787878787878787878787878787878", len: 100, expected: "58c287c73dc3bbecade0e9be8d6a59716e9ff1e0ed678ccb7a948573bdb780987ff9953edf5d54eb489c7ece9390aeb9ec53e62a613beef75f984802a738888fbe5fc61ed512628f3518e5c037b93857d08b32864934e2c7cebfdf3b3d9ad9fab005d6f5" },
    PlusVector { etype: 19, key: "20b53a1ff1c54cacc1e792416f7f4438", input: "696e707574", len: 1, expected: "85" },
    PlusVector { etype: 19, key: "20b53a1ff1c54cacc1e792416f7f4438", input: "696e707574", len: 32, expected: "85918ae81a936b818a95f825b658e8f1fe9094f9d999f1f7f30c403e26a9223e" },
    PlusVector { etype: 19, key: "20b53a1ff1c54cacc1e792416f7f4438", input: "66697874757265207072662b20696e707574", len: 67, expected: "42ce647307580cd93a7c3eed9caac4bba6331f8c6ba362d2726d309151a1b324819f83380f8b391783e965fbf8f8107ba431e4bc968b52310e401faa944814b37df5c0" },
    PlusVector { etype: 19, key: "20b53a1ff1c54cacc1e792416f7f4438", input: "", len: 5, expected: "17783688e8" },
    PlusVector { etype: 19, key: "20b53a1ff1c54cacc1e792416f7f4438", input: "78787878787878787878787878787878787878787878787878787878787878787878787878787878", len: 100, expected: "d186e9e795bd166d1e5ae122a6e8b53d3de767dcb3d1f43ee09f22527784640f67f9c85621ccffe52db8942dc875a6feb3d7be5a1dc4a83b7ce444b3dcaed5e8a4faa82e260a48f61cac7aa8a4100e6cca0508714d4a0bb76b658b451cc85e275d5a6877" },
    PlusVector { etype: 20, key: "7471cdd2b5012683d6a3005bbac242d017cab37417d45d2a311cb17b8dec2e0b", input: "696e707574", len: 1, expected: "11" },
    PlusVector { etype: 20, key: "7471cdd2b5012683d6a3005bbac242d017cab37417d45d2a311cb17b8dec2e0b", input: "696e707574", len: 48, expected: "11c5f790f46ea5bff4b301b9a26b776ffde276896bb939cce32fc054875744a5ab115a70b039c6bbe7708c3aed0f202b" },
    PlusVector { etype: 20, key: "7471cdd2b5012683d6a3005bbac242d017cab37417d45d2a311cb17b8dec2e0b", input: "66697874757265207072662b20696e707574", len: 99, expected: "d1d0dd7d79874e185cb98cdb8e3d2e8ea4b437de808532ecc1ce632794e3b99ac7af0f06f4a3e32c8bedda3ead452e9f0f39bf8e0a446e0938a8fa3553c675854433e4181c61b956d9c84a35ee078d6bd237639c8f11aecb2c95022a3dd00aa878a10f" },
    PlusVector { etype: 20, key: "7471cdd2b5012683d6a3005bbac242d017cab37417d45d2a311cb17b8dec2e0b", input: "", len: 5, expected: "fe9a17848f" },
    PlusVector { etype: 20, key: "7471cdd2b5012683d6a3005bbac242d017cab37417d45d2a311cb17b8dec2e0b", input: "78787878787878787878787878787878787878787878787878787878787878787878787878787878", len: 100, expected: "16128d6b8ff273aab438b8f36471bbd0e5e6f7862868582b88e6a660ef3b188478af086381c93918cea84712a51fbca7933ff40718bb08a40faff2d58bb2b0e088886bb7d866036a72183443dca2a02c2f1e77cf144ec7b76931976ee970de22d71a4372" },

];

/// `krb5_c_fx_cf2_simple` of host libk5crypto 1.22.1 with fixed keys and peppers `peppera`, `pepperb`.
const CF2_HOST: &[CfVector] = &[

    CfVector { etype: 17, key1: "3a825ddb45e6a293480ebec8b88673bd", key2: "8a4327948e2d7e5fa0b58b95e09caddd", pepper1: "peppera", pepper2: "pepperb", expected: "e22a24a4d3deee5d9a0f1be9acbe910a" },
    CfVector { etype: 18, key1: "4d1481a5e25c5ad520b328ac1a1a67204e33d6005ad04b1c1b3d415f76e41eff", key2: "3b5972d19c563b2c83c8cbc7652a09d571dd7cf2722e513d64396cdccf72b7ac", pepper1: "peppera", pepper2: "pepperb", expected: "a83e0e4acb4d46f959ef456671c0ae829b8794d0f3f647b9dd58eba9fb993002" },
    CfVector { etype: 23, key1: "16b8ae6ef569f1f4fe2d08b81e032abc", key2: "27881a36f69b1465e552fdd86bcd529d", pepper1: "peppera", pepper2: "pepperb", expected: "9268a3ae79ecf6b00eddb449806e0964" },
    CfVector { etype: 19, key1: "20b53a1ff1c54cacc1e792416f7f4438", key2: "904597184449661d14b96de9a71329c7", pepper1: "peppera", pepper2: "pepperb", expected: "627695f1ed97a12b2a6f0b6d429a695b" },
    CfVector { etype: 20, key1: "7471cdd2b5012683d6a3005bbac242d017cab37417d45d2a311cb17b8dec2e0b", key2: "966f0d70bfd85471693a0bc0a842c476cecccd922abe3f4116f66f31b73394ac", pepper1: "peppera", pepper2: "pepperb", expected: "d5427cf5435fe115ae32cdc8f884c8baab772c8da0744ba8f72332f5ce6615ef" },

];
