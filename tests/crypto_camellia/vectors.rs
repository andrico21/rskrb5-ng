// Generated from RFC 6803 section 10, MIT krb5 1.22.2 src/tests/gssapi/t_prf.c and host MIT libk5crypto 1.22.1 (gen_camellia_vectors.py in the evidence archive); do not edit.

/// An RFC 6803 string-to-key row: both key sizes for one input.
#[derive(Clone, Copy, Debug)]
struct S2kVector {
    /// PBKDF2 iteration count.
    iterations: u32,
    /// Pass phrase, hex.
    password: &'static str,
    /// Salt, hex.
    salt: &'static str,
    /// Expected 128-bit key, hex.
    key128: &'static str,
    /// Expected 256-bit key, hex.
    key256: &'static str,
}

/// An RFC 6803 key-derivation row (usage 2).
#[derive(Clone, Copy, Debug)]
struct KdfVector {
    /// Key size in bits.
    bits: u32,
    /// Base key, hex.
    key: &'static str,
    /// `Kc`, hex.
    kc: &'static str,
    /// `Ke`, hex.
    ke: &'static str,
    /// `Ki`, hex.
    ki: &'static str,
}

/// An RFC 6803 sample encryption.
#[derive(Clone, Copy, Debug)]
struct EncVector {
    /// Key size in bits.
    bits: u32,
    /// Base key, hex.
    key: &'static str,
    /// Key usage (the RFC lists none; found by search and fixed here, see the evidence log).
    usage: u32,
    /// Plaintext text.
    plain: &'static str,
    /// Confounder, hex.
    confounder: &'static str,
    /// Expected ciphertext with the checksum, hex.
    cipher: &'static str,
}

/// An RFC 6803 sample checksum.
#[derive(Clone, Copy, Debug)]
struct CksumVector {
    /// Key size in bits.
    bits: u32,
    /// Base key, hex.
    key: &'static str,
    /// Key usage.
    usage: u32,
    /// Message text.
    plain: &'static str,
    /// Expected checksum, hex.
    tag: &'static str,
}

/// A string-to-key row of libk5crypto with the default parameters.
#[derive(Clone, Copy, Debug)]
struct HostS2kVector {
    /// Etype ID.
    etype: i32,
    /// Pass phrase, hex.
    password: &'static str,
    /// Salt, hex.
    salt: &'static str,
    /// Expected key, hex.
    key: &'static str,
}

/// A `krb5_c_make_checksum` row of libk5crypto.
#[derive(Clone, Copy, Debug)]
struct HostCksumVector {
    /// Etype ID.
    etype: i32,
    /// Key, hex.
    key: &'static str,
    /// Key usage.
    usage: u32,
    /// Message, hex.
    msg: &'static str,
    /// Expected checksum, hex.
    tag: &'static str,
}

/// A `krb5_c_encrypt` row of libk5crypto (random confounder).
#[derive(Clone, Copy, Debug)]
struct HostEncVector {
    /// Etype ID.
    etype: i32,
    /// Key, hex.
    key: &'static str,
    /// Key usage.
    usage: u32,
    /// Plaintext, hex.
    plain: &'static str,
    /// Ciphertext with the checksum, hex.
    cipher: &'static str,
}

/// RFC 6803 section 10, string-to-key.
const S2K: &[S2kVector] = &[
    S2kVector { iterations: 1, password: "70617373776f7264", salt: "415448454e412e4d49542e4544557261656275726e", key128: "57d0297298ffd9d35de5a47fb4bde24b", key256: "b9d6828b2056b7be656d88a123b1fac68214ac2b727ecf5f69afe0c4df2a6d2c" },
    S2kVector { iterations: 2, password: "70617373776f7264", salt: "415448454e412e4d49542e4544557261656275726e", key128: "73f1b53aa0f310f93b1de8ccaa0cb152", key256: "83fc5866e5f8f4c6f38663c65c87549f342bc47ed394dc9d3cd4d163ade375e3" },
    S2kVector { iterations: 1200, password: "70617373776f7264", salt: "415448454e412e4d49542e4544557261656275726e", key128: "8e571145452855575fd916e7b04487aa", key256: "77f421a6f25e138395e837e5d85d385b4c1bfd772e112cd9208ce72a530b15e6" },
    S2kVector { iterations: 1200, password: "58585858585858585858585858585858585858585858585858585858585858585858585858585858585858585858585858585858585858585858585858585858", salt: "706173732070687261736520657175616c7320626c6f636b2073697a65", key128: "8bf6c3ef709b981dbb585d086843be05", key256: "119fe2a1cb0b1be010b9067a73db63ed4665b4e53a98d178035dcfe843a6b9b0" },
    S2kVector { iterations: 1200, password: "5858585858585858585858585858585858585858585858585858585858585858585858585858585858585858585858585858585858585858585858585858585858", salt: "7061737320706872617365206578636565647320626c6f636b2073697a65", key128: "5752ac8d6ad1ccfe8430b312871c2f74", key256: "614d5dfc0ba6d390b412b89ae4d5b088b612b316510994679ddb4383c7126ddf" },
    S2kVector { iterations: 5, password: "70617373776f7264", salt: "1234567878563412", key128: "00498fd916bfc1c2b1031c170801b381", key256: "11083a00bdfe6a41b2f19716d6202f0afa94289afe8b27a049bd28b1d76c389a" },
    S2kVector { iterations: 50, password: "f09d849e", salt: "4558414d504c452e434f4d7069616e697374", key128: "cc75c7fd260f1c1658011fcc0d560616", key256: "163b768c6db148b4eec7163df5aed70e206b68cec078bc069ed68a7ed36b1ecc" },
];

/// RFC 6803 section 10, key derivation for usage 2.
const KDF: &[KdfVector] = &[
    KdfVector { bits: 128, key: "57d0297298ffd9d35de5a47fb4bde24b", kc: "d155775a209d05f02b38d42a389e5a56", ke: "64df83f85a532f17577d8c37035796ab", ki: "3e4fbdf30fb8259c425cb6c96f1f4635" },
    KdfVector { bits: 256, key: "b9d6828b2056b7be656d88a123b1fac68214ac2b727ecf5f69afe0c4df2a6d2c", kc: "e467f9a9552bc7d3155a6220af9c19220eeed4ff78b0d1e6a1544991461a9e50", ke: "412aefc362a7285fc3966c6a5181e7605ae675235b6d549fbfc9ab6630a4c604", ki: "fa624fa0e523993fa388aefdc67e67ebcd8c08e8a0246b1d73b0d1dd9fc582b0" },
];

/// RFC 6803 section 10, sample encryptions.
const ENC: &[EncVector] = &[
    EncVector { bits: 128, key: "1dc46a8d763f4f93742bcba3387576c3", usage: 0, plain: "", confounder: "b69822a19a6b09c0ebc8557d1f1b6c0a", cipher: "c466f1871069921edb7c6fde244a52db0ba10edc197bdb8006658ca3ccce6eb8" },
    EncVector { bits: 128, key: "5027bc231d0f3a9d23333f1ca6fdbe7c", usage: 1, plain: "1", confounder: "6f2fc3c2a166fd8898967a83de9596d9", cipher: "842d21fd950311c0dd464a3f4be8d6da88a56d559c9b47d3f9a85067af661559b8" },
    EncVector { bits: 128, key: "a1bb61e805f9ba6dde8fdbddc05cdea0", usage: 2, plain: "9 bytesss", confounder: "a5b4a71e077aeef93c8763c18fdb1f10", cipher: "619ff072e36286ff0a28deb3a352ec0d0edf5c5160d663c901758ccf9d1ed33d71db8f23aabf8348a0" },
    EncVector { bits: 128, key: "2ca27a5faf5532244506434e1cef6676", usage: 3, plain: "13 bytes byte", confounder: "19fee40d810c524b5b22f01874c693da", cipher: "b8eca3167ae6315512e59f98a7c500205e5f63ff3bb389af1c41a21d640d8615c9ed3fbeb05ab6acb67689b5ea" },
    EncVector { bits: 128, key: "7824f8c16f83ff354c6bf7515b973f43", usage: 4, plain: "30 bytes bytes bytes bytes byt", confounder: "ca7a7ab4be192dabd603506db19c39e2", cipher: "a26a3905a4ffd5816b7b1e27380d08090c8ec1f304496e1abdcd2bdcd1dffc660989e117a713ddbb57a4146c1587cba4356665591d2240282f5842b105a5" },
    EncVector { bits: 256, key: "b61c86cc4e5d2757545ad423399fb7031ecab913cbb900bd7a3c6dd8bf92015b", usage: 0, plain: "", confounder: "3cbbd2b45917941067f96599bb98926c", cipher: "03886d03310b47a6d8f06d7b94d1dd837ecce315ef652aff620859d94a259266" },
    EncVector { bits: 256, key: "1b97fe0a190e2021eb30753e1b6e1e77b0754b1d684610355864104963463833", usage: 1, plain: "1", confounder: "def487fcebe6de6346d4da4521bba2d2", cipher: "2c9c1570133c99bf6a34bc1b0212002fd194338749db4135497a347cfcd9d18a12" },
    EncVector { bits: 256, key: "32164c5b434d1d1538e4cfd9be8040fe8c4ac7acc4b93d3314d2133668147a05", usage: 2, plain: "9 bytesss", confounder: "ad4ff904d34e555384b14100fc465f88", cipher: "9c6de75f812de7ed0d28b2963557a115640998275b0af5152709913ff52a2a9c8e63b872f92e64c839" },
    EncVector { bits: 256, key: "b038b132cd8e06612267fab7170066d88aeccba0b744bfc60dc89bca182d0715", usage: 3, plain: "13 bytes byte", confounder: "cf9bca6df1144e0c0af9b8f34c90d514", cipher: "eeec85a9813cdc536772ab9b42defc5706f726e975dde05a87eb5406ea324ca185c9986b42aabe794b84821bee" },
    EncVector { bits: 256, key: "ccfcd349bf4c6677e86e4b02b8eab924a546ac731cf9bf6989b996e7d6bfbba7", usage: 4, plain: "30 bytes bytes bytes bytes byt", confounder: "644def38da35007275878d216855e228", cipher: "0e44680985855f2d1f1812529ca83bfd8e349de6fd9ada0baaa048d68e265febf34ad1255a344999ad37146887a6c6845731ac7f46376a0504cd06571474" },
];

/// RFC 6803 section 10, sample checksums.
const CKSUM: &[CksumVector] = &[
    CksumVector { bits: 128, key: "1dc46a8d763f4f93742bcba3387576c3", usage: 7, plain: "abcdefghijk", tag: "1178e6c5c47a8c1ae0c4b9c7d4eb7b6b" },
    CksumVector { bits: 128, key: "5027bc231d0f3a9d23333f1ca6fdbe7c", usage: 8, plain: "ABCDEFGHIJKLMNOPQRSTUVWXYZ", tag: "d1b34f7004a731f23a0c00bf6c3f753a" },
    CksumVector { bits: 256, key: "b61c86cc4e5d2757545ad423399fb7031ecab913cbb900bd7a3c6dd8bf92015b", usage: 9, plain: "123456789", tag: "87a12cfd2b96214810f01c826e7744b1" },
    CksumVector { bits: 256, key: "32164c5b434d1d1538e4cfd9be8040fe8c4ac7acc4b93d3314d2133668147a05", usage: 10, plain: "!@#$%^&*()!@#$%^&*()!@#$%^&*()", tag: "3fa0b42355e52b189187294aa252ab64" },
];

/// `krb5_c_string_to_key` of host libk5crypto 1.22.1 with the default parameters.
const HOST_S2K: &[HostS2kVector] = &[
    HostS2kVector { etype: 25, password: "70617373776f7264", salt: "415448454e412e4d49542e4544557261656275726e", key: "f7624a7bde4208095e74911a43df6645" },
    HostS2kVector { etype: 25, password: "70707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070", salt: "4558414d504c452e434f4d73616c74", key: "d45da929e8ba42656b5f8af352daf18b" },
    HostS2kVector { etype: 26, password: "70617373776f7264", salt: "415448454e412e4d49542e4544557261656275726e", key: "ddeb562476d4f365aea927a40c79b27c8de9b1ce2eb4e629e11fd562da43dba5" },
    HostS2kVector { etype: 26, password: "70707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070", salt: "4558414d504c452e434f4d73616c74", key: "7755fa38766da93652f72649e8af2be81c9baade1ab3067c95d1acdc7d3bec18" },
];

/// `krb5_c_make_checksum` of host libk5crypto 1.22.1 (types 17 and 18).
const HOST_CKSUM: &[HostCksumVector] = &[
    HostCksumVector { etype: 25, key: "2f3f869a71059d50b19627a01238946d", usage: 7, msg: "6162636465666768696a6b", tag: "86b6f26e35cce09cd7c8e584fbec047f" },
    HostCksumVector { etype: 25, key: "2f3f869a71059d50b19627a01238946d", usage: 8, msg: "", tag: "898bc050dda4a2dbd85108df47cde9ac" },
    HostCksumVector { etype: 25, key: "2f3f869a71059d50b19627a01238946d", usage: 9, msg: "78787878787878787878787878787878", tag: "303073c82de9422ae2f01843a4009478" },
    HostCksumVector { etype: 25, key: "2f3f869a71059d50b19627a01238946d", usage: 10, msg: "79797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979", tag: "2542e2ebfe843f70831589e08fab17aa" },
    HostCksumVector { etype: 26, key: "33582ee71d10ab80e9eadfb0b7dd3a28676501ff3d36c1226345c30aea2083ce", usage: 7, msg: "6162636465666768696a6b", tag: "5ef8bd12fc81a4531cc171c8a5aaa4e7" },
    HostCksumVector { etype: 26, key: "33582ee71d10ab80e9eadfb0b7dd3a28676501ff3d36c1226345c30aea2083ce", usage: 8, msg: "", tag: "f6590c079fc36b5a116f6bd733a9efa3" },
    HostCksumVector { etype: 26, key: "33582ee71d10ab80e9eadfb0b7dd3a28676501ff3d36c1226345c30aea2083ce", usage: 9, msg: "78787878787878787878787878787878", tag: "635b95bbd32b2d88e8c176076c6cac8a" },
    HostCksumVector { etype: 26, key: "33582ee71d10ab80e9eadfb0b7dd3a28676501ff3d36c1226345c30aea2083ce", usage: 10, msg: "79797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979", tag: "9025b6bbb2227bb1d4b99ebec4a99b17" },
];

/// `krb5_c_encrypt` of host libk5crypto 1.22.1.
const HOST_ENC: &[HostEncVector] = &[
    HostEncVector { etype: 25, key: "2f3f869a71059d50b19627a01238946d", usage: 1, plain: "", cipher: "de46b6274707dce5fdb93ccdb301766ae0acc7bddb998ef38b8bc16259b681be" },
    HostEncVector { etype: 25, key: "2f3f869a71059d50b19627a01238946d", usage: 2, plain: "31", cipher: "5d7f43d569f12c14dd5f10d22aa84f91e4c1f1ccb7dd88b8a8eec44857142c5d37" },
    HostEncVector { etype: 25, key: "2f3f869a71059d50b19627a01238946d", usage: 3, plain: "392062797465737373", cipher: "9228923e504190bb55da3b469b2db0dd3cdc8cc3646ad2e52161cfec713bfc01c9a44466a3b5f33d56" },
    HostEncVector { etype: 25, key: "2f3f869a71059d50b19627a01238946d", usage: 4, plain: "7369787465656e2d627974652d6d7367", cipher: "23e8d3e20d471dab1776f5b36f824e46685e50889760a1acf24d8d65ec0f266906b0ab69d3cd8b2c25e0ec7511297af4" },
    HostEncVector { etype: 25, key: "2f3f869a71059d50b19627a01238946d", usage: 5, plain: "736576656e7465656e2d627974652d6d7367", cipher: "ea8c8718411e8f654637393fdbbbf5a3208799146424fe10fe3269a180229930d94d56d049c0c1c7e89f55ddec343322682d" },
    HostEncVector { etype: 25, key: "2f3f869a71059d50b19627a01238946d", usage: 6, plain: "7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a", cipher: "b83809d9142c041a5be447a4440790f6853588ad6cbbe1aa5549c6f5dfe106d4864e9a9a7ee78ebfeb785a3914370693ce72cb62ada8a98de1910b73815e7b" },
    HostEncVector { etype: 25, key: "2f3f869a71059d50b19627a01238946d", usage: 7, plain: "7777777777777777777777777777777777777777777777777777777777777777", cipher: "e9b6e011b9133da71f78516e3500696b037a1dbfcb72504b672117f845a5e0c0d52c90b52d048fe5de1ed1de923e512ceab37cefd8ee567fa2b528b1e58a2ef0" },
    HostEncVector { etype: 25, key: "2f3f869a71059d50b19627a01238946d", usage: 24, plain: "767676767676767676767676767676767676767676767676767676767676767676", cipher: "98517d4a44a76172e2d0b2fda09ab73a81949d1e4f5d2c7b5f8c376aa206f3c8c88bd7e84c0fa41f0aa88cbeebdd4c2cc026354dbd2461e179b46a323dbc38ed71" },
    HostEncVector { etype: 25, key: "2f3f869a71059d50b19627a01238946d", usage: 1024, plain: "757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575", cipher: "24e8b27c3c4de7a02b13b97468a1e24e5444567f277d5f71b250c12486517eb3dbdb1b45d79fe3e4cbc6b191d038b0ad7f4e8c992057503b13f575ee61814e2aca00285a19c174067fbfe2b67f37df3df267ef323d14ddc05101504bf36426c867d6c2ab74f4c38e98299af2f3cad1c51ac1d4b78a8ba806a321af63f7c827059fed55b7750d48f938700831de678262ede4145adb88b7b2" },
    HostEncVector { etype: 26, key: "33582ee71d10ab80e9eadfb0b7dd3a28676501ff3d36c1226345c30aea2083ce", usage: 1, plain: "", cipher: "4cb18fc871789a9cb7caaf27fe3a6067fabfbb8962029c774576b012f4f3c09c" },
    HostEncVector { etype: 26, key: "33582ee71d10ab80e9eadfb0b7dd3a28676501ff3d36c1226345c30aea2083ce", usage: 2, plain: "31", cipher: "bf21a11045748fe3e001b8128896bc91fbf43fa21f91da24e8f83fb185befa7920" },
    HostEncVector { etype: 26, key: "33582ee71d10ab80e9eadfb0b7dd3a28676501ff3d36c1226345c30aea2083ce", usage: 3, plain: "392062797465737373", cipher: "6792c601a0be23045ea919206b0b1bd90b0413c78ee98799895397870e516dc2e30f5f325e80c4e61e" },
    HostEncVector { etype: 26, key: "33582ee71d10ab80e9eadfb0b7dd3a28676501ff3d36c1226345c30aea2083ce", usage: 4, plain: "7369787465656e2d627974652d6d7367", cipher: "4d480ed56b0dd36780e3cc5735f5e1ba33a6be1dae05060570db9f3a5dafe7761cee80365fe256ca476304c5fe18f689" },
    HostEncVector { etype: 26, key: "33582ee71d10ab80e9eadfb0b7dd3a28676501ff3d36c1226345c30aea2083ce", usage: 5, plain: "736576656e7465656e2d627974652d6d7367", cipher: "c7655a99df07ceb1441201e535433e7e48d839e2f16bd686f065fab1d32d0f9cd9fb918af24f15176b088ada46a5751a2647" },
    HostEncVector { etype: 26, key: "33582ee71d10ab80e9eadfb0b7dd3a28676501ff3d36c1226345c30aea2083ce", usage: 6, plain: "7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a", cipher: "a8dda44a9ab509f069ad88fc9431955b18ea405e2b965ee6ea7dcb5c4e828ec6c655884961cfc33d7cc9f737db5facf5d2892e4b58bd5673eff2e55066fb38" },
    HostEncVector { etype: 26, key: "33582ee71d10ab80e9eadfb0b7dd3a28676501ff3d36c1226345c30aea2083ce", usage: 7, plain: "7777777777777777777777777777777777777777777777777777777777777777", cipher: "3257a27e062c6e3e66286d9385d20fba7b566422bc5f91b5f49ce349bd701a80ffc060b20bc3383e414c96454c569fd1e01c7b2e582f92ff0646c3f571f52cd2" },
    HostEncVector { etype: 26, key: "33582ee71d10ab80e9eadfb0b7dd3a28676501ff3d36c1226345c30aea2083ce", usage: 24, plain: "767676767676767676767676767676767676767676767676767676767676767676", cipher: "e6ee12875206c46e597b2ab9ecca89abfa6bb14a9f5a4e3604daed1a47adf688fc1300bfe3122e216cd6732b4294cd995eeb8836c7a78a1bc15aca649e1ba667fe" },
    HostEncVector { etype: 26, key: "33582ee71d10ab80e9eadfb0b7dd3a28676501ff3d36c1226345c30aea2083ce", usage: 1024, plain: "757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575", cipher: "e755052daf30c3b1931c1b8371d7c139e171bab3d5b100e9df30f0eb4867207d4d134e75959ee2fcd6c6257d46783379fde2dfc4ca522a746fac39dfe8b01a400cf1e8e604dff0bb567179ef5c09ed695ddfd99772ca68e5d38c52064da59faa65bb804be8b02746538287a505f6bd8d63faa536c37e024d8de3ba54df86081d97aa1a2c5b1b559588389c1961b8869dcb8d12e7805a8968" },
];



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

/// `src/tests/gssapi/t_prf.c` (krb5-1.22.2-final): out1 = PARTIAL key (subkey) with empty input, out2 = FULL key (acceptor subkey) with the 61-byte string; 44 bytes each.
const GSS: &[GssVector] = &[

    GssVector { etype: 25, key1: "866e0466a178279a32ac0bda92b72aeb", out1: "97fbb354bf341c3a160dcc86a7a910fda824601df67768797baceebf5d250ae929dec9760772084267f50a54", key2: "d4893fd37da1a211e12dd1e03e0f03b7", out2: "1dee2ff126ca563a2a2326b9dd3f0095013257414c83fad4398901013d55f367c82681186b7b2fe62f746ba4" },
    GssVector { etype: 26, key1: "203071b1ae77bd3d6fce70174af95c225b1ced46b35cf52b6479efeb47e6b063", out1: "9b30020634c10fda28420cee7b96b70a90a771ced43ad8346554163e5949cbae2fb8ef36afb6b32ce75116a0", key2: "a171ad582c1afbbad52abd622ee6b6a14d19bf95c6914b2ba40ffd99a88ec660", out2: "a47cbb6e104dcc77e4db48a7a474b977f2fb6a7a1ab652317d50508ae72b7be2e4e4ba24164e029cbacf786b" },

];

/// `krb5_c_prfplus` of host libk5crypto 1.22.1 (`gen_mit_vectors.py`).
const PLUS: &[PlusVector] = &[

    PlusVector { etype: 25, key: "2f3f869a71059d50b19627a01238946d", input: "696e707574", len: 1, expected: "cd" },
    PlusVector { etype: 25, key: "2f3f869a71059d50b19627a01238946d", input: "696e707574", len: 16, expected: "cd5c77a97f6a043104a78fb87b1512ad" },
    PlusVector { etype: 25, key: "2f3f869a71059d50b19627a01238946d", input: "66697874757265207072662b20696e707574", len: 35, expected: "71130e01f29f457d9688df6b2ec6efb20bfda268a63fbe84cc4e5c7f70a750c2f90a5a" },
    PlusVector { etype: 25, key: "2f3f869a71059d50b19627a01238946d", input: "", len: 5, expected: "af822039db" },
    PlusVector { etype: 25, key: "2f3f869a71059d50b19627a01238946d", input: "78787878787878787878787878787878787878787878787878787878787878787878787878787878", len: 100, expected: "ce9a0f4a4fadbbd4584f0b71821fb60ea3d9436e5153632040574e2e012f85570265796a0c6fe79ef2cc74d8dc21e968ea2b7dac3a62859e75bd5621677dd4bdf708e8abac0d76b42672cb6dbd8d489394d9d125dcb8916c2114984a386a998dd1070aef" },
    PlusVector { etype: 26, key: "33582ee71d10ab80e9eadfb0b7dd3a28676501ff3d36c1226345c30aea2083ce", input: "696e707574", len: 1, expected: "fd" },
    PlusVector { etype: 26, key: "33582ee71d10ab80e9eadfb0b7dd3a28676501ff3d36c1226345c30aea2083ce", input: "696e707574", len: 16, expected: "fd37defa2a63173a62c341e016a1c69b" },
    PlusVector { etype: 26, key: "33582ee71d10ab80e9eadfb0b7dd3a28676501ff3d36c1226345c30aea2083ce", input: "66697874757265207072662b20696e707574", len: 35, expected: "62118a7d6ec86f2c83a4bf047bb2fc3663cb4951899802dc3d6edf9dc9d59d3291d292" },
    PlusVector { etype: 26, key: "33582ee71d10ab80e9eadfb0b7dd3a28676501ff3d36c1226345c30aea2083ce", input: "", len: 5, expected: "428708a339" },
    PlusVector { etype: 26, key: "33582ee71d10ab80e9eadfb0b7dd3a28676501ff3d36c1226345c30aea2083ce", input: "78787878787878787878787878787878787878787878787878787878787878787878787878787878", len: 100, expected: "4203ece76877e571e6f5e35fd79790df6dd67b480cd55648715341bb87cd2735180dc052395e71094120e0ded9b4418a494565d192d8d8c0805bbb5022fed61e32ded0cedec65fbe543c005aec1c2ba0773f21a7b9667c42d3a99d29e4d7b9031c4aef8e" },

];

/// `krb5_c_fx_cf2_simple` of host libk5crypto 1.22.1 with fixed keys and peppers `peppera`, `pepperb`.
const CF2_HOST: &[CfVector] = &[

    CfVector { etype: 25, key1: "2f3f869a71059d50b19627a01238946d", key2: "50df66e52cb5266fecbb3e2ebd13e1b9", pepper1: "peppera", pepper2: "pepperb", expected: "3a16122a00af9c67168ca704277bb1d5" },
    CfVector { etype: 26, key1: "33582ee71d10ab80e9eadfb0b7dd3a28676501ff3d36c1226345c30aea2083ce", key2: "47c2e951eaf949fc272b9b8d80d96eef32fc20b4f992f8af989d5b59ba615d55", pepper1: "peppera", pepper2: "pepperb", expected: "692782c13ee65be459b503e3a54b415cf3e16679a7f6659fecc0cb5bc12bc9e5" },

];
