//! RFC 9588 appendix C test vectors, replayed through the client with the
//! recorded private scalar `y`; the SHA-1 vector exercises only the always
//! compiled key derivation.

use core::error::Error;
#[cfg(feature = "spake")]
use core::iter;

use sha1::{Digest, Sha1};

#[cfg(feature = "spake")]
use super::{Client, Group, Message, Policy, Step, group};
use super::{Derivation, Params, kdf};
use crate::keytab::EncryptionKey;
#[cfg(feature = "spake")]
use crate::{crypto::KerberosEtype, error::Spake};

/// One appendix C vector; every field is hex.
struct Vector {
    /// The appendix C heading.
    name: &'static str,
    /// Enctype of the initial reply key.
    etype: i32,
    /// Group number; -1 is the SHA-1 copy of edwards25519 that exercises two hash blocks.
    group: i32,
    /// The initial reply key.
    key: &'static str,
    /// The PRF+ output that produces `w`.
    wbytes: &'static str,
    /// The client's private scalar `y`.
    #[cfg(feature = "spake")]
    private: &'static str,
    /// The client's element `S`.
    client_element: &'static str,
    /// The shared element `K`.
    shared: &'static str,
    /// The rejected optimistic challenge, when the vector has one.
    #[cfg(feature = "spake")]
    optimistic: Option<&'static str>,
    /// The support message, when the vector has one.
    support: Option<&'static str>,
    /// The challenge the client answers.
    challenge: &'static str,
    /// Transcript hash after the challenge.
    thash_challenge: &'static str,
    /// Transcript hash after the client's element.
    thash_final: &'static str,
    /// The KDC-REQ-BODY.
    body: &'static str,
    /// `K'[0]` to `K'[3]`.
    derived: [&'static str; 4],
}

/// The vectors of RFC 9588 appendix C, in document order.
///
/// The last one is the appendix's illustration of a hypothetical SHA-1 copy of
/// edwards25519 (group -1), which MIT's `t_vectors.c` does not carry. Its
/// multiplier and transcript hashes are the appendix's, but its printed `K'[n]`
/// do not follow from the section 7 algorithm: this crate and an independent
/// Python implementation (RFC 3961/3962 PRF, `KRB-FX-CF2` and section 7 over
/// `hashlib` and `cryptography`, which reproduces every other vector) agree on
/// different values, so `K'[n]` here are that implementation's output.
const VECTORS: [Vector; 10] = [
    Vector {
        name: "des3-cbc-sha1 edwards25519",
        etype: 16,
        group: 1,
        key: "850bb51358548cd05e86768c313e3bfef7511937dcf72c3e",
        wbytes: "686d84730cb8679ae95416c6567c6a63f2c9cef124f7a3371ae81e11cad42a37",
        #[cfg(feature = "spake")]
        private: "500b294797b8b042aca1bedc0f5931a4f52c537b3608b2d05cc8a2372f439f25",
        client_element: "5d10705e0d1e43d5dbf30240ccfbde4a0230c70d4c79147ab0b317edad2f8ae7",
        shared: "25bde0d875f0feb5755f45ba5e857889d916ecf7476f116aa31dc3e037ec4292",
        #[cfg(feature = "spake")]
        optimistic: None,
        support: Some("a0093007a0053003020101"),
        challenge: "a1363034a003020101a122042018f511e750c97b592acd30db7d9e5fca660389102e6bf610c1bfbed4616c8362a20930073005a003020101",
        thash_challenge: "22bb2271e34d329d52073c70b1d1187973181f0bc7614266bb79ee80d3335175",
        thash_final: "eaaa08807d0616026ff51c849efbf35ba0ce3c5300e7d486da46351b13d4605b",
        body: "3075a00703050000000000a1143012a003020101a10b30091b077261656275726ea2101b0e415448454e412e4d49542e454455a3233021a003020102a11a30181b066b72627467741b0e415448454e412e4d49542e454455a511180f31393730303130313030303030305aa703020100a8053003020110",
        derived: [
            "baf12fae7cd958cbf1a29bfbc71f89ce49e03e295d89dafd",
            "64f73dd9c41908206bcec1f719026b574f9d13463d7a2520",
            "0454520b086b152c455829e6baeff78a61dfe9e3d04a895d",
            "4a92260b25e3ef94c125d5c24c3e5bced5b37976e67f25c4",
        ],
    },
    Vector {
        name: "rc4-hmac edwards25519",
        etype: 23,
        group: 1,
        key: "8846f7eaee8fb117ad06bdd830b7586c",
        wbytes: "7c86659d29cf2b2ea93bfe79c3cefb8850e82215b3ea6fcd896561d48048f49c",
        #[cfg(feature = "spake")]
        private: "18fe7c1512708c7fd06db270361f04593775bc634ceaf45347e5c11c38aae017",
        client_element: "38f8d4568090148ebc9fd17c241b4cc2769505a7ca6f3f7104417b72b5b5cf54",
        shared: "03e75edd2cd7e7677642dd68736e91700953ac55dc650e3c2a1b3b4acdb800f8",
        #[cfg(feature = "spake")]
        optimistic: None,
        support: Some("a0093007a0053003020101"),
        challenge: "a1363034a003020101a12204207db465f1c08c64983a19f560bce966fe5306c4b447f70a5bca14612a92da1d63a20930073005a003020101",
        thash_challenge: "3cde9ed9b562a09d816885b6c225f7336d9e2674bb4df903dfc894d963a2af42",
        thash_final: "f4b208458017de6ef7f6a307d47d87db6c2af1d291b726860f68bc08bfef440a",
        body: "3075a00703050000000000a1143012a003020101a10b30091b077261656275726ea2101b0e415448454e412e4d49542e454455a3233021a003020102a11a30181b066b72627467741b0e415448454e412e4d49542e454455a511180f31393730303130313030303030305aa703020100a8053003020117",
        derived: [
            "770b720c82384cbb693e85411eedecba",
            "621deec88e2865837c4d3462bb50a1d5",
            "1cc8f6333b9fa3b42662fd9914fbd5bb",
            "edb4032b7fc3806d5211a534dcbc390c",
        ],
    },
    Vector {
        name: "aes128-cts-hmac-sha1-96 edwards25519",
        etype: 17,
        group: 1,
        key: "fca822951813fb252154c883f5ee1cf4",
        wbytes: "0d591b197b667e083c2f5f98ac891d3c9f99e710e464e62f1fb7c9b67936f3eb",
        #[cfg(feature = "spake")]
        private: "b877afe8612b406d96be85bd9f19d423e95be96c0e1e0b5824127195c3ed5917",
        client_element: "fbe08f7f96cd5d4139e7c9eccb95e79b8ace41e270a60198c007df18525b628e",
        shared: "c2f7f99997c585e6b686ceb62db42f17cc70932def3bb4cf009e36f22ea5473d",
        #[cfg(feature = "spake")]
        optimistic: None,
        support: Some("a0093007a0053003020101"),
        challenge: "a1363034a003020101a12204209e9311d985c1355e022d7c3c694ad8d6f7ad6d647b68a90b0fe46992818002daa20930073005a003020101",
        thash_challenge: "4512310282c01b39dd9aebd0cc2a5e532ed077a6c11d4c973c4593d525078797",
        thash_final: "951285f107c87f0169b9c918a1f51f60cb1a75b9f8bb799a99f53d03add94b5f",
        body: "3075a00703050000000000a1143012a003020101a10b30091b077261656275726ea2101b0e415448454e412e4d49542e454455a3233021a003020102a11a30181b066b72627467741b0e415448454e412e4d49542e454455a511180f31393730303130313030303030305aa703020100a8053003020111",
        derived: [
            "548022d58a7c47eae8c49dccf6baa407",
            "b2c9ba0e13fc8ab3a9d96b51b601cf4a",
            "69f0ee5fdb6c237e7fcd38d9f87df1bd",
            "78f91e2240b5ee528a5cc8d7cbebfba5",
        ],
    },
    Vector {
        name: "aes256-cts-hmac-sha1-96 edwards25519",
        etype: 18,
        group: 1,
        key: "01b897121d933ab44b47eb5494db15e50eb74530dbdae9b634d65020ff5d88c1",
        wbytes: "e902341590a1b4bb4d606a1c643cccb3f2108f1b6aa97b381012b9400c9e3f4e",
        #[cfg(feature = "spake")]
        private: "88b859df58ef5c69bacdfe681c582754eaab09a74dc29cff50b328613c232f55",
        client_element: "9e2cc32908fc46273279ec75354b4aeafa70c3d99a4d507175ed70d80b255dda",
        shared: "cf57f58f6e60169d2ecc8f20bb923a8e4c16e5bc95b9e64b5dc870da7026321b",
        #[cfg(feature = "spake")]
        optimistic: None,
        support: Some("a0093007a0053003020101"),
        challenge: "a1363034a003020101a12204206f301aacae1220e91be42868c163c5009aeea1e9d9e28afcfc339cda5e7105b5a20930073005a003020101",
        thash_challenge: "23a5e72eb4dedd1ca860f43736c458f0775c3bb1370a26af8a9374d521d70ec9",
        thash_final: "1c605649d4658b58cbe79a5faf227acc16c355c58b7dade022f90c158fe5ed8e",
        body: "3075a00703050000000000a1143012a003020101a10b30091b077261656275726ea2101b0e415448454e412e4d49542e454455a3233021a003020102a11a30181b066b72627467741b0e415448454e412e4d49542e454455a511180f31393730303130313030303030305aa703020100a8053003020112",
        derived: [
            "a9bfa71c95c575756f922871524b65288b3f695573ccc0633e87449568210c23",
            "1865a9ee1ef0640ec28ac007391cac624c42639c714767a974e99aa10003015f",
            "e57781513fefdb978e374e156b0da0c1a08148f5eb26b8e157ac3c077e28bf49",
            "008e6487293c3cc9fabbbcdd8b392d6dcb88222317fd7fe52d12fbc44fa047f1",
        ],
    },
    Vector {
        name: "aes256-cts-hmac-sha1-96 P-256",
        etype: 18,
        group: 2,
        key: "01b897121d933ab44b47eb5494db15e50eb74530dbdae9b634d65020ff5d88c1",
        wbytes: "eb2984af18703f94dd5288b8596cd36988d0d4e83bfb2b44de14d0e95e2090bd",
        #[cfg(feature = "spake")]
        private: "e07405eb215663abc1f254b8adc0da7a16febaa011af923d79fdef7c42930b33",
        client_element: "021d07dc31266fc7cfd904ce2632111a169b7ec730e5f74a7e79700f86638e13c8",
        shared: "0268489d7a9983f2fde69c6e6a1307e9d252259264f5f2dfc32f58cca19671e79b",
        #[cfg(feature = "spake")]
        optimistic: None,
        support: Some("a0093007a0053003020102"),
        challenge: "a1373035a003020102a1230421024f62078ceb53840d02612195494d0d0d88de21feeb81187c71cbf3d01e71788da20930073005a003020101",
        thash_challenge: "0a142afca77c2e92b066572a90389eac40a6b1f1ed8b534d342591c0e7727e00",
        thash_final: "20ad3c1a9a90fc037d1963a1c4bfb15ab4484d7b6cf07b12d24984f14652de60",
        body: "3075a00703050000000000a1143012a003020101a10b30091b077261656275726ea2101b0e415448454e412e4d49542e454455a3233021a003020102a11a30181b066b72627467741b0e415448454e412e4d49542e454455a511180f31393730303130313030303030305aa703020100a8053003020112",
        derived: [
            "7d3b906f7be49932db22cd3463f032d06c9c078be4b1d076d201fc6e61ef531e",
            "17d74e36f8993841fbb7feb12fa4f011243d3ae4d2ace55b39379294bbc4db2c",
            "d192c9044081a2aa6a97a6c69e2724e8e5671c2c9ce073dd439cdbaf96d7dab0",
            "41e5bad6b67f12c53ce0e2720dd6a9887f877bf9463c2d5209c74c36f8d776b7",
        ],
    },
    Vector {
        name: "aes256-cts-hmac-sha1-96 P-384",
        etype: 18,
        group: 3,
        key: "01b897121d933ab44b47eb5494db15e50eb74530dbdae9b634d65020ff5d88c1",
        wbytes: "0304cfc55151c6bbe889653db96dbfe0ba4acafc024c1e8840cb3a486f6d80c16e1b8974016aa4b7fa43042a9b3825b1",
        #[cfg(feature = "spake")]
        private: "5b7c709acb175a5afb82860deabca8d0b341facdff0ac0f1a425799aa905d7507e1ea9c573581a81467437419466e472",
        client_element: "020d5adfdb92bc377041cf5837412574c5d13e0f4739208a4f0c859a0a302bc6a533440a245b9d97a0d34af5016a20053d",
        shared: "0264aa8c61da9600dfb0beb5e46550d63740e4ef29e73f1a30d543eb43c25499037ad16538586552761b093cf0e37c703a",
        #[cfg(feature = "spake")]
        optimistic: None,
        support: Some("a0093007a0053003020103"),
        challenge: "a1473045a003020103a133043102a1524603ef14f184696f854229d3397507a66c63f841ba748451056be07879ac298912387b1c5cdff6381c264701be57a20930073005a003020101",
        thash_challenge: "4d4095d9f94552e15015881a3f2cf4581be83217cf7ad830d2f051dba3ec8caa6e354eaa85738d7035317ac557f8c294",
        thash_final: "5ac0d99ef9e5a73998797fe64f074673e3952dec4c7d1aacce8b75f64d2b0276a901cb8539b4e8ed69e4db0ce805b47b",
        body: "3075a00703050000000000a1143012a003020101a10b30091b077261656275726ea2101b0e415448454e412e4d49542e454455a3233021a003020102a11a30181b066b72627467741b0e415448454e412e4d49542e454455a511180f31393730303130313030303030305aa703020100a8053003020112",
        derived: [
            "b917d37c16dd1d8567fbe379f64e1ee36ca3fd127aa4e60f97e4afa3d9e56d91",
            "93d40079dab229b9c79366829f4e7e7282e6a4b943ac7bac69922d516673f49a",
            "bfc4f16f12f683e71589f9a888e232875ef293ac9793db6c919567cd7b94bcd4",
            "3630e2b5b99938e7506733141e8ec344166f6407e5fc2ef107c156e764d1bc20",
        ],
    },
    Vector {
        name: "aes256-cts-hmac-sha1-96 P-521",
        etype: 18,
        group: 4,
        key: "01b897121d933ab44b47eb5494db15e50eb74530dbdae9b634d65020ff5d88c1",
        wbytes: "de3a095a2b2386eff3eb15b735398da1caf95bc8425665d82370aff58b0471f34a57bccddf1ebf0a2965b58a93ee5b45e85d1a5435d1c8c83662999722d542831f9a",
        #[cfg(feature = "spake")]
        private: "003e2e2950656fa231e959acdd984d125e7fa59cec98126cbc8f3888447911ebcd49428a1c22d5fdb76a19fbeb1d9edfa3da6cf55b158b53031d05d51433ade9b2b4",
        client_element: "02004d142d87477841f6ba053c8f651f3395ad264b7405ca5911fb9a55abd454fef658a5f9ed97d1efac68764e9092fa15b9e0050880d78e95fd03abf59317916822b5",
        shared: "03007c303f62f09282cc849490805bd4457a6793a832cbeb55df427db6a31e99b055d5dc99756d24d47b70ad8b6015b0fb8742a718462ed423b90fa3fe631ac13fa916",
        #[cfg(feature = "spake")]
        optimistic: None,
        support: Some("a0093007a0053003020104"),
        challenge: "a1593057a003020104a145044302017d3de19a3ec53d0174905665ef37947d142535102cd9809c0dfbd0dfe007353d54cf406ce2a59950f2bb540df6fbe75f8bbbef811c9ba06cc275adbd96756696eca20930073005a003020101",
        thash_challenge: "554405860f8a80944228f1fa2466411dcf236162aa385e1289131b39e1fd59f25e58b4c281ff059c28dc20f5803b87c67571ce64cea01b39a21819d1ef1cdc7f",
        thash_final: "8d6a89ae4d80cc4e47b6f4e48ea3e57919cc69598d0d3dc7c8bd49b6f1db1409ca0312944cd964e213aba98537041102237cff5b331e5347a0673869b412302e",
        body: "3075a00703050000000000a1143012a003020101a10b30091b077261656275726ea2101b0e415448454e412e4d49542e454455a3233021a003020102a11a30181b066b72627467741b0e415448454e412e4d49542e454455a511180f31393730303130313030303030305aa703020100a8053003020112",
        derived: [
            "1eb3d10bee8fab483adcd3eb38f3ebf1f4feb8db96ecc035f563cf2e1115d276",
            "482b92781ce57f49176e4c94153cc622fe247a7dbe931d1478315f856f085890",
            "a2c215126dd3df280aab5a27e1e0fb7e594192cbff8d6d8e1b6f1818d9bb8fac",
            "cc06603de984324013a01f888de6d43b410a4da2dea53509f30e433c352fb668",
        ],
    },
    Vector {
        name: "aes256-cts-hmac-sha1-96 edwards25519, accepted optimistic challenge",
        etype: 18,
        group: 1,
        key: "01b897121d933ab44b47eb5494db15e50eb74530dbdae9b634d65020ff5d88c1",
        wbytes: "e902341590a1b4bb4d606a1c643cccb3f2108f1b6aa97b381012b9400c9e3f4e",
        #[cfg(feature = "spake")]
        private: "785d6801a2490df028903ac6449b105f2ff0db895b252953cdc2076649526103",
        client_element: "2a8f70f46cee9030700037b77f22cec7970dcc238e3e066d9d726baf183992c6",
        shared: "d3c5e4266aa6d1b2873a97ce8af91c7e4d7a7ac456acced7908d34c561ad8fa6",
        #[cfg(feature = "spake")]
        optimistic: None,
        support: None,
        challenge: "a1363034a003020101a122042083523b35f1565006cbfc4f159885467c2fb9bc6fe23d36cb1da43d199f1a3118a20930073005a003020101",
        thash_challenge: "0332da8ba3095ccd127c51740cb905bac76e90725e769570b9d8338e6d62a7f2",
        thash_final: "26f07f9f8965307434d11ea855461d41e0cbabcc0a1bab48ecee0c6c1a4292b7",
        body: "3075a00703050000000000a1143012a003020101a10b30091b077261656275726ea2101b0e415448454e412e4d49542e454455a3233021a003020102a11a30181b066b72627467741b0e415448454e412e4d49542e454455a511180f31393730303130313030303030305aa703020100a8053003020112",
        derived: [
            "4569ec08b5de5c3cc19d941725913ace8d74524b521a341dc746acd5c3784d92",
            "0d96ce1a4ac0f2e280a0cfc31742b06461d83d04ae45433db2d80478dd882a4c",
            "58018c19315a1ba5d5bb9813b58029f0aec18a6f9ca59e0847de1c60bc25945c",
            "ed7e9bffd68c54d86fb19cd3c03f317f88a71ad9a5e94c28581d93fc4ec72b6a",
        ],
    },
    Vector {
        name: "aes256-cts-hmac-sha1-96 P-521, rejected edwards25519 challenge",
        etype: 18,
        group: 4,
        key: "01b897121d933ab44b47eb5494db15e50eb74530dbdae9b634d65020ff5d88c1",
        wbytes: "de3a095a2b2386eff3eb15b735398da1caf95bc8425665d82370aff58b0471f34a57bccddf1ebf0a2965b58a93ee5b45e85d1a5435d1c8c83662999722d542831f9a",
        #[cfg(feature = "spake")]
        private: "01ded675ebf74fe30c9a53710f577e9cf84f09f6048fe245a4600004884cc167733f9a9e43108fb83babe8754cd37cbd7025e28bc9ff870f084c7244f536285e25b4",
        client_element: "02016c64995e804416f748fd5fa3aa678cbc7cbb596a4f523132dc8af7ce84e541f484a2c74808c6b21dcf7775baefa6753398425becc7b838b210ac5daa0cb0b710e2",
        shared: "0200997f4848ae2e7a98c23d14ac662030743ab37fccc2a45f1c721114f40bcc80fe6ec6aba49868f8aea1aa994d50e81b86d3e4d3c1130c8695b68907c673d9e5886a",
        #[cfg(feature = "spake")]
        optimistic: Some(
            "a1363034a003020102a122042047ca8c24c3a4a70b6eca228322529dadcfa85cf58faceecf5d5c02907b9e2deba20930073005a003020101",
        ),
        support: Some("a0093007a0053003020104"),
        challenge: "a1593057a003020104a145044302014cb2e5b592ece5990f0ef30d308c061de1598bc4272b4a6599bed466fd1521693642abcf4dbe36ce1a2d13967de45f6c4f8d0fa8e14428bf03fb96ef5f1ed3e645a20930073005a003020101",
        thash_challenge: "cb925b8baeae5e2867ab5b10ae1c941c4ff4b58a4812c1f7bd1c862ad480a8e1c6fcd5e88d846a2045e385841c91a75ad2035f0ff692717608e2a5a90842eff2",
        thash_final: "d0efed5e3e2c39c26034756d92a66fec3082ad793d0197f3f89ad36026f146a3996e548aa3fc49e2e82f8cac5d132c505aa475b39e7be79cded22c26c41aa777",
        body: "3075a00703050000000000a1143012a003020101a10b30091b077261656275726ea2101b0e415448454e412e4d49542e454455a3233021a003020102a11a30181b066b72627467741b0e415448454e412e4d49542e454455a511180f31393730303130313030303030305aa703020100a8053003020112",
        derived: [
            "631fcc8596e7f40e59045950d72aa0b7bac2810a07b767050e983841cf3a2d4c",
            "881464920117074dbc67155a8f3341d1121ef65f78ea0380bfa81a134c1c47b1",
            "377b72ac3af2caad582d73ae4682fd56b531ee56706200dd6c38c42b8219837a",
            "35ad8e4d580ed3f0d15ad928329773c081bd19f9a56363f3a5f77c7e66108c26",
        ],
    },
    Vector {
        name: "AES256 edwards25519 SHA-1 group number -1",
        etype: 18,
        group: -1,
        key: "01b897121d933ab44b47eb5494db15e50eb74530dbdae9b634d65020ff5d88c1",
        wbytes: "26da6b118cee6fa5ea795ed32d61490d82b2f11102312f3f2fc04fb01c93df91",
        #[cfg(feature = "spake")]
        private: "10fc4e0bb1a902e58f632a1ea0bceb366360ac985f46996d956a02572bfcf050",
        client_element: "f9a7fa352930dedb422d567700bfcd39ba221e7f9ac3e6b36f2b63b68b88642c",
        shared: "6f61d6b18323b6c3ddaac7c56712845335384f095d3e116f69feb926a04f1340",
        #[cfg(feature = "spake")]
        optimistic: None,
        support: Some("a0093007a00530030201ff"),
        challenge: "a1363034a0030201ffa12204202289a4f3c613e6e1df95e94aaa3c127dc062b9fceec3f9b62378dc729d61d0e3a20930073005a003020101",
        thash_challenge: "f5c051eb75290f92142cbbe80557ec2c85902c94",
        thash_final: "9e26a3b148400c8f9cb8545331e4e7dcab399cc0",
        body: "3075a00703050000000000a1143012a003020101a10b30091b077261656275726ea2101b0e415448454e412e4d49542e454455a3233021a003020102a11a30181b066b72627467741b0e415448454e412e4d49542e454455a511180f31393730303130313030303030305aa703020100a8053003020112",
        derived: [
            "780e23e927760d7e237e5e80e7eb633f871b9b880067359d4127b72578f41d48",
            "4671675f6c8108e535635f922c1b942623bf3e9bdc53bddb609a251d33f6a819",
            "6bc958c090c4549a68bf2bc6d8806a5c341a051b1202baf5fcc2c838fd95632a",
            "3d73e8476f3b867efec49d79c28201032d734d5f2dde738fce7a8a4fd91c034b",
        ],
    },
];

/// Hex-decode a vector field.
fn bytes(text: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(hex::decode(text)?)
}

#[cfg(feature = "spake")]
/// The draw that makes the client choose `y`: edwards25519 takes 64 bytes and
/// multiplies the reduced value by the cofactor, so it receives `y / 8`.
fn draw(chosen: Group, y: &[u8]) -> Vec<u8> {
    if chosen == Group::Edwards25519 {
        let shifted = y
            .iter()
            .zip(y.iter().skip(1).copied().chain([0_u8]))
            .map(|(low, high)| (low >> 3_u8) | (high << 5_u8));
        shifted.chain([0_u8; 32]).collect()
    } else {
        y.to_vec()
    }
}

#[cfg(feature = "spake")]
/// An entropy source that answers the first request with `first` and zeros after it.
fn replay(first: Vec<u8>) -> impl FnMut(&mut [u8]) -> Result<(), Spake> {
    let mut pending = Some(first);
    move |buffer: &mut [u8]| {
        let source = pending.take().unwrap_or_default();
        for (slot, byte) in buffer
            .iter_mut()
            .zip(source.iter().chain(iter::repeat(&0_u8)))
        {
            *slot = *byte;
        }
        Ok(())
    }
}

#[cfg(feature = "spake")]
/// Every vector of the four registered groups, replayed through [`Client`].
///
/// It checks the support message, the response element `S`, `K'[0]` as the
/// reply key, the factor sealed in `K'[1]`, the multiplier, the shared
/// element, both transcript hashes and `K'[2]`, `K'[3]`.
#[test]
fn rfc9588_vectors_replay_through_the_client() -> Result<(), Box<dyn Error>> {
    for vector in VECTORS.iter().filter(|vector| vector.group > 0_i32) {
        let chosen = Group::from_id(vector.group).ok_or("unknown group")?;
        let key = EncryptionKey::new(vector.etype, bytes(vector.key)?);
        let (body, challenge, y) = (
            bytes(vector.body)?,
            bytes(vector.challenge)?,
            bytes(vector.private)?,
        );
        let mut client = Client::new(Policy::new([chosen]));
        let first = vector
            .optimistic
            .map_or_else(Vec::new, |text| hex::decode(text).unwrap_or_default());
        if vector.support.is_some() {
            let step = client.process_with(
                &first,
                &body,
                || Ok::<_, Spake>(key.clone()),
                &mut replay(Vec::new()),
            )?;
            let Step::Support(padata) = step else {
                return Err(format!("{}: no support message", vector.name).into());
            };
            assert_eq!(
                hex::encode(&padata.value),
                vector.support.unwrap_or_default(),
                "{}: support",
                vector.name
            );
        }
        let step = client.process_with(
            &challenge,
            &body,
            || Ok::<_, Spake>(key.clone()),
            &mut replay(draw(chosen, &y)),
        )?;
        let Step::Response { padata, reply_key } = step else {
            return Err(format!("{}: no response", vector.name).into());
        };
        let Message::Response { pubkey, factor } = Message::decode(&padata.value)? else {
            return Err(format!("{}: not a response", vector.name).into());
        };
        assert_eq!(
            hex::encode(&pubkey),
            vector.client_element,
            "{}: S",
            vector.name
        );
        assert_eq!(
            hex::encode(reply_key.value()),
            vector.derived[0],
            "{}: K'[0]",
            vector.name
        );
        let etype = KerberosEtype::from_etype_id(vector.etype).ok_or("etype")?;
        let plaintext = etype.decrypt_message(
            &bytes(vector.derived[1])?,
            &factor.cipher,
            super::KEY_USAGE_SPAKE,
        )?;
        let (factor_der, padding) = plaintext.split_at_checked(7).ok_or("short factor")?;
        assert_eq!(
            hex::encode(factor_der),
            "3005a003020101",
            "{}: SF-NONE in K'[1]",
            vector.name
        );
        assert!(
            padding.iter().all(|byte| *byte == 0),
            "{}: factor padding",
            vector.name
        );
        let wbytes = kdf::multiplier(&key, vector.group, chosen.params().mult_len)?;
        assert_eq!(hex::encode(&wbytes), vector.wbytes, "{}: w", vector.name);
        let shared = group::exchange(
            chosen,
            &wbytes,
            &bytes(&vector_t(vector)?)?,
            &mut replay(draw(chosen, &y)),
        )?;
        assert_eq!(
            hex::encode(&*shared.result),
            vector.shared,
            "{}: K",
            vector.name
        );
        assert_transcript_and_keys(vector, &chosen.params())?;
    }
    Ok(())
}

#[cfg(feature = "spake")]
/// The KDC element of a vector: the `pubkey` of its challenge.
fn vector_t(vector: &Vector) -> Result<String, Box<dyn Error>> {
    let Message::Challenge {
        group: _,
        pubkey,
        factors: _,
    } = Message::decode(&bytes(vector.challenge)?)?
    else {
        return Err("not a challenge".into());
    };
    Ok(hex::encode(&pubkey))
}

/// Both transcript hashes and `K'[0]` to `K'[3]` of `vector` under `params`.
fn assert_transcript_and_keys(vector: &Vector, params: &Params) -> Result<(), Box<dyn Error>> {
    let support = vector
        .support
        .map_or_else(Vec::new, |text| hex::decode(text).unwrap_or_default());
    let after = kdf::update(params, None, &[&support, &bytes(vector.challenge)?]);
    assert_eq!(
        hex::encode(&after),
        vector.thash_challenge,
        "{}: transcript after challenge",
        vector.name
    );
    let last = kdf::update(params, Some(&after), &[&bytes(vector.client_element)?]);
    assert_eq!(
        hex::encode(&last),
        vector.thash_final,
        "{}: final transcript",
        vector.name
    );
    let key = EncryptionKey::new(vector.etype, bytes(vector.key)?);
    let (wbytes, result, body) = (
        bytes(vector.wbytes)?,
        bytes(vector.shared)?,
        bytes(vector.body)?,
    );
    let derivation = Derivation {
        params: *params,
        key: &key,
        wbytes: &wbytes,
        result: &result,
        thash: &last,
        body: &body,
    };
    for (index, expected) in (0_u32..).zip(vector.derived) {
        assert_eq!(
            hex::encode(kdf::derive(&derivation, index)?.value()),
            expected,
            "{}: K'[{index}]",
            vector.name
        );
    }
    Ok(())
}

/// SHA-1 over the concatenation of `parts`: the hash of the appendix C copy of
/// edwards25519 with group number -1, whose 20-byte output needs two blocks
/// for an AES-256 seed.
fn sha1(parts: &[&[u8]]) -> Vec<u8> {
    parts
        .iter()
        .fold(Sha1::new(), Digest::chain_update)
        .finalize()
        .to_vec()
}

/// The SHA-1 vector: transcript and the multi-block `K'[n]` derivation.
#[test]
fn rfc9588_sha1_vector_derives_two_hash_blocks() -> Result<(), Box<dyn Error>> {
    let vector = VECTORS
        .iter()
        .find(|vector| vector.group == -1_i32)
        .ok_or("no SHA-1 vector")?;
    let key = EncryptionKey::new(vector.etype, bytes(vector.key)?);
    assert_eq!(
        hex::encode(kdf::multiplier(&key, -1, 32)?),
        vector.wbytes,
        "w of group -1"
    );
    let params = Params {
        id: -1,
        name: "edwards25519 with SHA-1",
        mult_len: 32,
        elem_len: 32,
        hash_len: 20,
        hash: sha1,
    };
    assert_transcript_and_keys(vector, &params)
}
