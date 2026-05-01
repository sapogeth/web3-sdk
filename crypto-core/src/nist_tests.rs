///
/// NIST ACVTS (Cryptographic Algorithm Validation Program) test vectors
///
/// Sources:
///   ECDH: NIST KAS ECC CDH Primitive — https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program
///   ECDSA: NIST FIPS 186-3 SigVer P-256/SHA-256
///   AES-GCM: NIST SP 800-38D GCM Test Vectors (256-bit key, 96-bit IV)
///   HKDF: RFC 5869 Appendix A (official NIST-referenced test vectors)
///

#[cfg(test)]
mod nist_ecdh {
    use crate::crypto::ecdh_secret;

    fn h(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i+2], 16).unwrap())
            .collect()
    }

    fn uncompressed_pub(x: &str, y: &str) -> [u8; 65] {
        let mut out = [0u8; 65];
        out[0] = 0x04;
        out[1..33].copy_from_slice(&h(x));
        out[33..65].copy_from_slice(&h(y));
        out
    }

    fn to32(v: Vec<u8>) -> [u8; 32] { v.try_into().unwrap() }

    // NIST KAS ECC CDH Primitive — P-256 (all 25 vectors)
    struct V { qx: &'static str, qy: &'static str, d: &'static str, z: &'static str }

    const VECTORS: &[V] = &[
        V { qx: "700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287", qy: "db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac", d: "7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534", z: "46fc62106420ff012e54a434fbdd2d25ccc5852060561e68040dd7778997bd7b" },
        V { qx: "809f04289c64348c01515eb03d5ce7ac1a8cb9498f5caa50197e58d43a86a7ae", qy: "b29d84e811197f25eba8f5194092cb6ff440e26d4421011372461f579271cda3", d: "38f65d6dce47676044d58ce5139582d568f64bb16098d179dbab07741dd5caf5", z: "057d636096cb80b67a8c038c890e887d1adfa4195e9b3ce241c8a778c59cda67" },
        V { qx: "a2339c12d4a03c33546de533268b4ad667debf458b464d77443636440ee7fec3", qy: "ef48a3ab26e20220bcda2c1851076839dae88eae962869a497bf73cb66faf536", d: "1accfaf1b97712b85a6f54b148985a1bdc4c9bec0bd258cad4b3d603f49f32c8", z: "2d457b78b4614132477618a5b077965ec90730a8c81a1c75d6d4ec68005d67ec" },
        V { qx: "df3989b9fa55495719b3cf46dccd28b5153f7808191dd518eff0c3cff2b705ed", qy: "422294ff46003429d739a33206c8752552c8ba54a270defc06e221e0feaf6ac4", d: "207c43a79bfee03db6f4b944f53d2fb76cc49ef1c9c4d34d51b6c65c4db6932d", z: "96441259534b80f6aee3d287a6bb17b5094dd4277d9e294f8fe73e48bf2a0024" },
        V { qx: "41192d2813e79561e6a1d6f53c8bc1a433a199c835e141b05a74a97b0faeb922", qy: "1af98cc45e98a7e041b01cf35f462b7562281351c8ebf3ffa02e33a0722a1328", d: "59137e38152350b195c9718d39673d519838055ad908dd4757152fd8255c09bf", z: "19d44c8d63e8e8dd12c22a87b8cd4ece27acdde04dbf47f7f27537a6999a8e62" },
        V { qx: "33e82092a0f1fb38f5649d5867fba28b503172b7035574bf8e5b7100a3052792", qy: "f2cf6b601e0a05945e335550bf648d782f46186c772c0f20d3cd0d6b8ca14b2f", d: "f5f8e0174610a661277979b58ce5c90fee6c9b3bb346a90a7196255e40b132ef", z: "664e45d5bba4ac931cd65d52017e4be9b19a515f669bea4703542a2c525cd3d3" },
        V { qx: "6a9e0c3f916e4e315c91147be571686d90464e8bf981d34a90b6353bca6eeba7", qy: "40f9bead39c2f2bcc2602f75b8a73ec7bdffcbcead159d0174c6c4d3c5357f05", d: "3b589af7db03459c23068b64f63f28d3c3c6bc25b5bf76ac05f35482888b5190", z: "ca342daa50dc09d61be7c196c85e60a80c5cb04931746820be548cdde055679d" },
        V { qx: "a9c0acade55c2a73ead1a86fb0a9713223c82475791cd0e210b046412ce224bb", qy: "f6de0afa20e93e078467c053d241903edad734c6b403ba758c2b5ff04c9d4229", d: "d8bf929a20ea7436b2461b541a11c80e61d826c0a4c9d322b31dd54e7f58b9c8", z: "35aa9b52536a461bfde4e85fc756be928c7de97923f0416c7a3ac8f88b3d4489" },
        V { qx: "94e94f16a98255fff2b9ac0c9598aac35487b3232d3231bd93b7db7df36f9eb9", qy: "d8049a43579cfa90b8093a94416cbefbf93386f15b3f6e190b6e3455fedfe69a", d: "0f9883ba0ef32ee75ded0d8bda39a5146a29f1f2507b3bd458dbea0b2bb05b4d", z: "605c16178a9bc875dcbff54d63fe00df699c03e8a888e9e94dfbab90b25f39b4" },
        V { qx: "e099bf2a4d557460b5544430bbf6da11004d127cb5d67f64ab07c94fcdf5274f", qy: "d9c50dbe70d714edb5e221f4e020610eeb6270517e688ca64fb0e98c7ef8c1c5", d: "2beedb04b05c6988f6a67500bb813faf2cae0d580c9253b6339e4a3337bb6c08", z: "f96e40a1b72840854bb62bc13c40cc2795e373d4e715980b261476835a092e0b" },
        V { qx: "f75a5fe56bda34f3c1396296626ef012dc07e4825838778a645c8248cff01658", qy: "33bbdf1b1772d8059df568b061f3f1122f28a8d819167c97be448e3dc3fb0c3c", d: "77c15dcf44610e41696bab758943eff1409333e4d5a11bbe72c8f6c395e9f848", z: "8388fa79c4babdca02a8e8a34f9e43554976e420a4ad273c81b26e4228e9d3a3" },
        V { qx: "2db4540d50230756158abf61d9835712b6486c74312183ccefcaef2797b7674d", qy: "62f57f314e3f3495dc4e099012f5e0ba71770f9660a1eada54104cdfde77243e", d: "42a83b985011d12303db1a800f2610f74aa71cdf19c67d54ce6c9ed951e9093e", z: "72877cea33ccc4715038d4bcbdfe0e43f42a9e2c0c3b017fc2370f4b9acbda4a" },
        V { qx: "cd94fc9497e8990750309e9a8534fd114b0a6e54da89c4796101897041d14ecb", qy: "c3def4b5fe04faee0a11932229fff563637bfdee0e79c6deeaf449f85401c5c4", d: "ceed35507b5c93ead5989119b9ba342cfe38e6e638ba6eea343a55475de2800b", z: "e4e7408d85ff0e0e9c838003f28cdbd5247cdce31f32f62494b70e5f1bc36307" },
        V { qx: "15b9e467af4d290c417402e040426fe4cf236bae72baa392ed89780dfccdb471", qy: "cdf4e9170fb904302b8fd93a820ba8cc7ed4efd3a6f2d6b05b80b2ff2aee4e77", d: "43e0e9d95af4dc36483cdd1968d2b7eeb8611fcce77f3a4e7d059ae43e509604", z: "ed56bcf695b734142c24ecb1fc1bb64d08f175eb243a31f37b3d9bb4407f3b96" },
        V { qx: "49c503ba6c4fa605182e186b5e81113f075bc11dcfd51c932fb21e951eee2fa1", qy: "8af706ff0922d87b3f0c5e4e31d8b259aeb260a9269643ed520a13bb25da5924", d: "b2f3600df3368ef8a0bb85ab22f41fc0e5f4fdd54be8167a5c3cd4b08db04903", z: "bc5c7055089fc9d6c89f83c1ea1ada879d9934b2ea28fcf4e4a7e984b28ad2cf" },
        V { qx: "19b38de39fdd2f70f7091631a4f75d1993740ba9429162c2a45312401636b29c", qy: "09aed7232b28e060941741b6828bcdfa2bc49cc844f3773611504f82a390a5ae", d: "4002534307f8b62a9bf67ff641ddc60fef593b17c3341239e95bdb3e579bfdc8", z: "9a4e8e657f6b0e097f47954a63c75d74fcba71a30d83651e3e5a91aa7ccd8343" },
        V { qx: "2c91c61f33adfe9311c942fdbff6ba47020feff416b7bb63cec13faf9b099954", qy: "6cab31b06419e5221fca014fb84ec870622a1b12bab5ae43682aa7ea73ea08d0", d: "4dfa12defc60319021b681b3ff84a10a511958c850939ed45635934ba4979147", z: "3ca1fc7ad858fb1a6aba232542f3e2a749ffc7203a2374a3f3d3267f1fc97b78" },
        V { qx: "a28a2edf58025668f724aaf83a50956b7ac1cfbbff79b08c3bf87dfd2828d767", qy: "dfa7bfffd4c766b86abeaf5c99b6e50cb9ccc9d9d00b7ffc7804b0491b67bc03", d: "1331f6d874a4ed3bc4a2c6e9c74331d3039796314beee3b7152fcdba5556304e", z: "1aaabe7ee6e4a6fa732291202433a237df1b49bc53866bfbe00db96a0f58224f" },
        V { qx: "a2ef857a081f9d6eb206a81c4cf78a802bdf598ae380c8886ecd85fdc1ed7644", qy: "563c4c20419f07bc17d0539fade1855e34839515b892c0f5d26561f97fa04d1a", d: "dd5e9f70ae740073ca0204df60763fb6036c45709bf4a7bb4e671412fad65da3", z: "430e6a4fba4449d700d2733e557f66a3bf3d50517c1271b1ddae1161b7ac798c" },
        V { qx: "ccd8a2d86bc92f2e01bce4d6922cf7fe1626aed044685e95e2eebd464505f01f", qy: "e9ddd583a9635a667777d5b8a8f31b0f79eba12c75023410b54b8567dddc0f38", d: "5ae026cfc060d55600717e55b8a12e116d1d0df34af831979057607c2d9c2f76", z: "1ce9e6740529499f98d1f1d71329147a33df1d05e4765b539b11cf615d6974d3" },
        V { qx: "c188ffc8947f7301fb7b53e36746097c2134bf9cc981ba74b4e9c4361f595e4e", qy: "bf7d2f2056e72421ef393f0c0f2b0e00130e3cac4abbcc00286168e85ec55051", d: "b601ac425d5dbf9e1735c5e2d5bdb79ca98b3d5be4a2cfd6f2273f150e064d9d", z: "4690e3743c07d643f1bc183636ab2a9cb936a60a802113c49bb1b3f2d0661660" },
        V { qx: "317e1020ff53fccef18bf47bb7f2dd7707fb7b7a7578e04f35b3beed222a0eb6", qy: "09420ce5a19d77c6fe1ee587e6a49fbaf8f280e8df033d75403302e5a27db2ae", d: "fefb1dda1845312b5fce6b81b2be205af2f3a274f5a212f66c0d9fc33d7ae535", z: "30c2261bd0004e61feda2c16aa5e21ffa8d7e7f7dbf6ec379a43b48e4b36aeb0" },
        V { qx: "45fb02b2ceb9d7c79d9c2fa93e9c7967c2fa4df5789f9640b24264b1e524fcb1", qy: "5c6e8ecf1f7d3023893b7b1ca1e4d178972ee2a230757ddc564ffe37f5c5a321", d: "334ae0c4693d23935a7e8e043ebbde21e168a7cba3fa507c9be41d7681e049ce", z: "2adae4a138a239dcd93c243a3803c3e4cf96e37fe14e6a9b717be9599959b11c" },
        V { qx: "a19ef7bff98ada781842fbfc51a47aff39b5935a1c7d9625c8d323d511c92de6", qy: "e9c184df75c955e02e02e400ffe45f78f339e1afe6d056fb3245f4700ce606ef", d: "2c4bde40214fcc3bfc47d4cf434b629acbe9157f8fd0282540331de7942cf09d", z: "2e277ec30f5ea07d6ce513149b9479b96e07f4b6913b1b5c11305c1444a1bc0b" },
        V { qx: "356c5a444c049a52fee0adeb7e5d82ae5aa83030bfff31bbf8ce2096cf161c4b", qy: "57d128de8b2a57a094d1a001e572173f96e8866ae352bf29cddaf92fc85b2f92", d: "85a268f9d7772f990c36b42b0a331adc92b5941de0b862d5d89a347cbf8faab0", z: "1e51373bd2c6044c129c436e742a55be2a668a85ae08441b6756445df5493857" },
    ];

    #[test]
    fn nist_ecdh_p256_all_25_vectors() {
        for (i, v) in VECTORS.iter().enumerate() {
            let pub_key = uncompressed_pub(v.qx, v.qy);
            let priv_key: [u8; 32] = to32(h(v.d));
            let expected: [u8; 32] = to32(h(v.z));

            let result = ecdh_secret(&priv_key, &pub_key)
                .unwrap_or_else(|e| panic!("ECDH vector {} failed: {}", i, e));

            assert_eq!(result, expected, "NIST ECDH P-256 vector {} mismatch", i);
        }
    }
}

#[cfg(test)]
mod nist_ecdsa {
    use crate::crypto::ec_verify;
    use sha2::{Sha256, Digest};

    fn h(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i+2], 16).unwrap())
            .collect()
    }

    fn uncompressed_pub(x: &str, y: &str) -> [u8; 65] {
        let mut out = [0u8; 65];
        out[0] = 0x04;
        out[1..33].copy_from_slice(&h(x));
        out[33..65].copy_from_slice(&h(y));
        out
    }

    /// Build minimal DER-encoded ECDSA signature from raw 32-byte r and s scalars.
    /// SEQUENCE { INTEGER r, INTEGER s }
    fn rs_to_der(r: &[u8], s: &[u8]) -> Vec<u8> {
        fn encode_int(n: &[u8]) -> Vec<u8> {
            // Strip leading zeros, but prepend 0x00 if high bit set
            let n = n.iter().skip_while(|&&b| b == 0).cloned().collect::<Vec<_>>();
            let n = if n.is_empty() { vec![0u8] } else { n };
            let n = if n[0] & 0x80 != 0 { [&[0u8], n.as_slice()].concat() } else { n };
            let mut out = vec![0x02, n.len() as u8];
            out.extend_from_slice(&n);
            out
        }
        let ri = encode_int(r);
        let si = encode_int(s);
        let inner_len = ri.len() + si.len();
        let mut der = vec![0x30, inner_len as u8];
        der.extend_from_slice(&ri);
        der.extend_from_slice(&si);
        der
    }

    struct SigVerVector {
        msg: &'static str,
        qx: &'static str,
        qy: &'static str,
        r: &'static str,
        s: &'static str,
        pass: bool,
    }

    // NIST FIPS 186-3 SigVer.rsp — [P-256,SHA-256] — all 15 vectors verbatim
    const VECTORS: &[SigVerVector] = &[
        // F(3-S): S tampered
        SigVerVector { pass: false, msg: "e4796db5f785f207aa30d311693b3702821dff1168fd2e04c0836825aefd850d9aa60326d88cde1a23c7745351392ca2288d632c264f197d05cd424a30336c19fd09bb229654f0222fcb881a4b35c290a093ac159ce13409111ff0358411133c24f5b8e2090d6db6558afc36f06ca1f6ef779785adba68db27a409859fc4c4a0", qx: "87f8f2b218f49845f6f10eec3877136269f5c1a54736dbdf69f89940cad41555", qy: "e15f369036f49842fac7a86c8a2b0557609776814448b8f5e84aa9f4395205e9", r: "d19ff48b324915576416097d2544f7cbdf8768b1454ad20e0baac50e211f23b0", s: "a3e81e59311cdfff2d4784949f7a2cb50ba6c3a91fa54710568e61aca3e847c6" },
        // F(2-R): R tampered
        SigVerVector { pass: false, msg: "069a6e6b93dfee6df6ef6997cd80dd2182c36653cef10c655d524585655462d683877f95ecc6d6c81623d8fac4e900ed0019964094e7de91f1481989ae1873004565789cbf5dc56c62aedc63f62f3b894c9c6f7788c8ecaadc9bd0e81ad91b2b3569ea12260e93924fdddd3972af5273198f5efda0746219475017557616170e", qx: "5cf02a00d205bdfee2016f7421807fc38ae69e6b7ccd064ee689fc1a94a9f7d2", qy: "ec530ce3cc5c9d1af463f264d685afe2b4db4b5828d7e61b748930f3ce622a85", r: "dc23d130c6117fb5751201455e99f36f59aba1a6a21cf2d0e7481a97451d6693", s: "d6ce7708c18dbf35d4f8aa7240922dc6823f2e7058cbc1484fcad1599db5018c" },
        // F(4-Q): Q tampered
        SigVerVector { pass: false, msg: "df04a346cf4d0e331a6db78cca2d456d31b0a000aa51441defdb97bbeb20b94d8d746429a393ba88840d661615e07def615a342abedfa4ce912e562af714959896858af817317a840dcff85a057bb91a3c2bf90105500362754a6dd321cdd86128cfc5f04667b57aa78c112411e42da304f1012d48cd6a7052d7de44ebcc01de", qx: "2ddfd145767883ffbb0ac003ab4a44346d08fa2570b3120dcce94562422244cb", qy: "5f70c7d11ac2b7a435ccfbbae02c3df1ea6b532cc0e9db74f93fffca7c6f9a64", r: "9913111cff6f20c5bf453a99cd2c2019a4e749a49724a08774d14e4c113edda8", s: "9467cd4cd21ecb56b0cab0a9a453b43386845459127a952421f5c6382866c5cc" },
        // P(0): valid
        SigVerVector { pass: true,  msg: "e1130af6a38ccb412a9c8d13e15dbfc9e69a16385af3c3f1e5da954fd5e7c45fd75e2b8c36699228e92840c0562fbf3772f07e17f1add56588dd45f7450e1217ad239922dd9c32695dc71ff2424ca0dec1321aa47064a044b7fe3c2b97d03ce470a592304c5ef21eed9f93da56bb232d1eeb0035f9bf0dfafdcc4606272b20a3", qx: "e424dc61d4bb3cb7ef4344a7f8957a0c5134e16f7a67c074f82e6e12f49abf3c", qy: "970eed7aa2bc48651545949de1dddaf0127e5965ac85d1243d6f60e7dfaee927", r: "bf96b99aa49c705c910be33142017c642ff540c76349b9dab72f981fd9347f4f", s: "17c55095819089c2e03b9cd415abdf12444e323075d98f31920b9e0f57ec871c" },
        // P(0): valid
        SigVerVector { pass: true,  msg: "73c5f6a67456ae48209b5f85d1e7de7758bf235300c6ae2bdceb1dcb27a7730fb68c950b7fcada0ecc4661d3578230f225a875e69aaa17f1e71c6be5c831f22663bac63d0c7a9635edb0043ff8c6f26470f02a7bc56556f1437f06dfa27b487a6c4290d8bad38d4879b334e341ba092dde4e4ae694a9c09302e2dbf443581c08", qx: "e0fc6a6f50e1c57475673ee54e3a57f9a49f3328e743bf52f335e3eeaa3d2864", qy: "7f59d689c91e463607d9194d99faf316e25432870816dde63f5d4b373f12f22a", r: "1d75830cd36f4c9aa181b2c4221e87f176b7f05b7c87824e82e396c88315c407", s: "cb2acb01dac96efc53a32d4a0d85d0c2e48955214783ecf50a4f0414a319c05a" },
        // F(2-R): R tampered
        SigVerVector { pass: false, msg: "666036d9b4a2426ed6585a4e0fd931a8761451d29ab04bd7dc6d0c5b9e38e6c2b263ff6cb837bd04399de3d757c6c7005f6d7a987063cf6d7e8cb38a4bf0d74a282572bd01d0f41e3fd066e3021575f0fa04f27b700d5b7ddddf50965993c3f9c7118ed78888da7cb221849b3260592b8e632d7c51e935a0ceae15207bedd548", qx: "a849bef575cac3c6920fbce675c3b787136209f855de19ffe2e8d29b31a5ad86", qy: "bf5fe4f7858f9b805bd8dcc05ad5e7fb889de2f822f3d8b41694e6c55c16b471", r: "548886278e5ec26bed811dbb72db1e154b6f17be70deb1b210107decb1ec2a5a", s: "e93bfebd2f14f3d827ca32b464be6e69187f5edbd52def4f96599c37d58eee75" },
        // F(4-Q): Q tampered
        SigVerVector { pass: false, msg: "7e80436bce57339ce8da1b5660149a20240b146d108deef3ec5da4ae256f8f894edcbbc57b34ce37089c0daa17f0c46cd82b5a1599314fd79d2fd2f446bd5a25b8e32fcf05b76d644573a6df4ad1dfea707b479d97237a346f1ec632ea5660efb57e8717a8628d7f82af50a4e84b11f21bdff6839196a880ae20b2a0918d58cd", qx: "3dfb6f40f2471b29b77fdccba72d37c21bba019efa40c1c8f91ec405d7dcc5df", qy: "f22f953f1e395a52ead7f3ae3fc47451b438117b1e04d613bc8555b7d6e6d1bb", r: "548886278e5ec26bed811dbb72db1e154b6f17be70deb1b210107decb1ec2a5a", s: "e93bfebd2f14f3d827ca32b464be6e69187f5edbd52def4f96599c37d58eee75" },
        // F(1-Msg): message tampered
        SigVerVector { pass: false, msg: "1669bfb657fdc62c3ddd63269787fc1c969f1850fb04c933dda063ef74a56ce13e3a649700820f0061efabf849a85d474326c8a541d99830eea8131eaea584f22d88c353965dabcdc4bf6b55949fd529507dfb803ab6b480cd73ca0ba00ca19c438849e2cea262a1c57d8f81cd257fb58e19dec7904da97d8386e87b84948169", qx: "69b7667056e1e11d6caf6e45643f8b21e7a4bebda463c7fdbc13bc98efbd0214", qy: "d3f9b12eb46c7c6fda0da3fc85bc1fd831557f9abc902a3be3cb3e8be7d1aa2f", r: "288f7a1cd391842cce21f00e6f15471c04dc182fe4b14d92dc18910879799790", s: "247b3c4e89a3bcadfea73c7bfd361def43715fa382b8c3edf4ae15d6e55e9979" },
        // F(3-S): S tampered
        SigVerVector { pass: false, msg: "3fe60dd9ad6caccf5a6f583b3ae65953563446c4510b70da115ffaa0ba04c076115c7043ab8733403cd69c7d14c212c655c07b43a7c71b9a4cffe22c2684788ec6870dc2013f269172c822256f9e7cc674791bf2d8486c0f5684283e1649576efc982ede17c7b74b214754d70402fb4bb45ad086cf2cf76b3d63f7fce39ac970", qx: "bf02cbcf6d8cc26e91766d8af0b164fc5968535e84c158eb3bc4e2d79c3cc682", qy: "069ba6cb06b49d60812066afa16ecf7b51352f2c03bd93ec220822b1f3dfba03", r: "f5acb06c59c2b4927fb852faa07faf4b1852bbb5d06840935e849c4d293d1bad", s: "049dab79c89cc02f1484c437f523e080a75f134917fda752f2d5ca397addfe5d" },
        // F(2-R): R tampered
        SigVerVector { pass: false, msg: "983a71b9994d95e876d84d28946a041f8f0a3f544cfcc055496580f1dfd4e312a2ad418fe69dbc61db230cc0c0ed97e360abab7d6ff4b81ee970a7e97466acfd9644f828ffec538abc383d0e92326d1c88c55e1f46a668a039beaa1be631a89129938c00a81a3ae46d4aecbf9707f764dbaccea3ef7665e4c4307fa0b0a3075c", qx: "224a4d65b958f6d6afb2904863efd2a734b31798884801fcab5a590f4d6da9de", qy: "178d51fddada62806f097aa615d33b8f2404e6b1479f5fd4859d595734d6d2b9", r: "87b93ee2fecfda54deb8dff8e426f3c72c8864991f8ec2b3205bb3b416de93d2", s: "4044a24df85be0cc76f21a4430b75b8e77b932a87f51e4eccbc45c263ebf8f66" },
        // F(3-S): S tampered
        SigVerVector { pass: false, msg: "4a8c071ac4fd0d52faa407b0fe5dab759f7394a5832127f2a3498f34aac287339e043b4ffa79528faf199dc917f7b066ad65505dab0e11e6948515052ce20cfdb892ffb8aa9bf3f1aa5be30a5bbe85823bddf70b39fd7ebd4a93a2f75472c1d4f606247a9821f1a8c45a6cb80545de2e0c6c0174e2392088c754e9c8443eb5af", qx: "43691c7795a57ead8c5c68536fe934538d46f12889680a9cb6d055a066228369", qy: "f8790110b3c3b281aa1eae037d4f1234aff587d903d93ba3af225c27ddc9ccac", r: "8acd62e8c262fa50dd9840480969f4ef70f218ebf8ef9584f199031132c6b1ce", s: "cfca7ed3d4347fb2a29e526b43c348ae1ce6c60d44f3191b6d8ea3a2d9c92154" },
        // F(1-Msg): message tampered
        SigVerVector { pass: false, msg: "0a3a12c3084c865daf1d302c78215d39bfe0b8bf28272b3c0b74beb4b7409db0718239de700785581514321c6440a4bbaea4c76fa47401e151e68cb6c29017f0bce4631290af5ea5e2bf3ed742ae110b04ade83a5dbd7358f29a85938e23d87ac8233072b79c94670ff0959f9c7f4517862ff829452096c78f5f2e9a7e4e9216", qx: "9157dbfcf8cf385f5bb1568ad5c6e2a8652ba6dfc63bc1753edf5268cb7eb596", qy: "972570f4313d47fc96f7c02d5594d77d46f91e949808825b3d31f029e8296405", r: "dfaea6f297fa320b707866125c2a7d5d515b51a503bee817de9faa343cc48eeb", s: "8f780ad713f9c3e5a4f7fa4c519833dfefc6a7432389b1e4af463961f09764f2" },
        // F(1-Msg): message tampered
        SigVerVector { pass: false, msg: "785d07a3c54f63dca11f5d1a5f496ee2c2f9288e55007e666c78b007d95cc28581dce51f490b30fa73dc9e2d45d075d7e3a95fb8a9e1465ad191904124160b7c60fa720ef4ef1c5d2998f40570ae2a870ef3e894c2bc617d8a1dc85c3c55774928c38789b4e661349d3f84d2441a3b856a76949b9f1f80bc161648a1cad5588e", qx: "072b10c081a4c1713a294f248aef850e297991aca47fa96a7470abe3b8acfdda", qy: "9581145cca04a0fb94cedce752c8f0370861916d2a94e7c647c5373ce6a4c8f5", r: "09f5483eccec80f9d104815a1be9cc1a8e5b12b6eb482a65c6907b7480cf4f19", s: "a4f90e560c5e4eb8696cb276e5165b6a9d486345dedfb094a76e8442d026378d" },
        // F(4-Q): Q tampered
        SigVerVector { pass: false, msg: "76f987ec5448dd72219bd30bf6b66b0775c80b394851a43ff1f537f140a6e7229ef8cd72ad58b1d2d20298539d6347dd5598812bc65323aceaf05228f738b5ad3e8d9fe4100fd767c2f098c77cb99c2992843ba3eed91d32444f3b6db6cd212dd4e5609548f4bb62812a920f6e2bf1581be1ebeebdd06ec4e971862cc42055ca", qx: "09308ea5bfad6e5adf408634b3d5ce9240d35442f7fe116452aaec0d25be8c24", qy: "f40c93e023ef494b1c3079b2d10ef67f3170740495ce2cc57f8ee4b0618b8ee5", r: "5cc8aa7c35743ec0c23dde88dabd5e4fcd0192d2116f6926fef788cddb754e73", s: "9c9c045ebaa1b828c32f82ace0d18daebf5e156eb7cbfdc1eff4399a8a900ae7" },
        // P(0): valid
        SigVerVector { pass: true,  msg: "60cd64b2cd2be6c33859b94875120361a24085f3765cb8b2bf11e026fa9d8855dbe435acf7882e84f3c7857f96e2baab4d9afe4588e4a82e17a78827bfdb5ddbd1c211fbc2e6d884cddd7cb9d90d5bf4a7311b83f352508033812c776a0e00c003c7e0d628e50736c7512df0acfa9f2320bd102229f46495ae6d0857cc452a84", qx: "2d98ea01f754d34bbc3003df5050200abf445ec728556d7ed7d5c54c55552b6d", qy: "9b52672742d637a32add056dfd6d8792f2a33c2e69dafabea09b960bc61e230a", r: "06108e525f845d0155bf60193222b3219c98e3d49424c2fb2a0987f825c17959", s: "62b5cdd591e5b507e560167ba8f6f7cda74673eb315680cb89ccbc4eec477dce" },
    ];

    #[test]
    fn nist_ecdsa_p256_sha256_sigver() {
        for (i, v) in VECTORS.iter().enumerate() {
            let pub_key   = uncompressed_pub(v.qx, v.qy);
            let msg_bytes = h(v.msg);
            let r_bytes   = h(v.r);
            let s_bytes   = h(v.s);

            // Build DER signature from raw (r, s) scalars
            let der = rs_to_der(&r_bytes, &s_bytes);

            // ec_verify uses VerifyingKey::verify() which hashes internally with SHA-256
            // So we pass the raw message, not the hash
            let result   = ec_verify(&msg_bytes, &der, &pub_key);
            let is_valid = result.unwrap_or(false);

            assert_eq!(
                is_valid, v.pass,
                "NIST ECDSA SigVer vector {} expected {}, got {}",
                i,
                if v.pass { "PASS" } else { "FAIL" },
                if is_valid { "PASS" } else { "FAIL" }
            );
        }
    }
}

#[cfg(test)]
mod nist_aes_gcm {
    use crate::crypto::{aead_encrypt, aead_decrypt};

    fn h(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i+2], 16).unwrap())
            .collect()
    }
    fn to32(v: Vec<u8>) -> [u8; 32] { v.try_into().unwrap() }
    fn to12(v: Vec<u8>) -> [u8; 12] { v.try_into().unwrap() }

    struct V {
        key: &'static str,
        iv:  &'static str,
        pt:  &'static str,
        aad: &'static str,
        ct:  &'static str,
        tag: &'static str,
    }

    // NIST SP 800-38D GCM — 256-bit key, 96-bit IV, PTlen=128 bits (16 bytes)
    const ENCRYPT: &[V] = &[
        V { key: "31bdadd96698c204aa9ce1448ea94ae1fb4a9a0b3c9d773b51bb1822666b8f22", iv: "0d18e06c7c725ac9e362e1ce", pt: "2db5168e932556f8089a0622981d017d", aad: "", ct: "fa4362189661d163fcd6a56d8bf0405a", tag: "d636ac1bbedd5cc3ee727dc2ab4a9489" },
        V { key: "460fc864972261c2560e1eb88761ff1c992b982497bd2ac36c04071cbb8e5d99", iv: "8a4a16b9e210eb68bcb6f58d", pt: "99e4e926ffe927f691893fb79a96b067", aad: "", ct: "133fc15751621b5f325c7ff71ce08324", tag: "ec4e87e0cf74a13618d0b68636ba9fa7" },
        V { key: "f78a2ba3c5bd164de134a030ca09e99463ea7e967b92c4b0a0870796480297e5", iv: "2bb92fcb726c278a2fa35a88", pt: "f562509ed139a6bbe7ab545ac616250c", aad: "", ct: "e2f787996e37d3b47294bf7ebba5ee25", tag: "00f613eee9bdad6c9ee7765db1cb45c0" },
        V { key: "48e6af212da1386500454c94a201640c2151b28079240e40d72d2a5fd7d54234", iv: "ef0ff062220eb817dc2ece94", pt: "c7afeecec1408ad155b177c2dc7138b0", aad: "", ct: "9432a620e6a22307e06a321d66846fd4", tag: "e3ea499192f2cd8d3ab3edfc55897415" },
        V { key: "79cd8d750fc8ea62a2714edcd9b32867c7c4da906c56e23a644552f5b812e75a", iv: "9bbfdb81015d2b57dead2de5", pt: "f980ad8c55ebd31ee6f98f44e92bff55", aad: "", ct: "41a34d1e759c859e91b8cf5d3ded1970", tag: "68cd98406d5b322571e750c30aa49834" },
        V { key: "130ae450c18efb851057aaa79575a0a090194be8b2c95469a0e8e380a8f48f42", iv: "b269115396f81b39e0c38f47", pt: "036cf36280dee8355c82abc4c1fdb778", aad: "", ct: "09f7568fd8181652e556f0dda5a49ed5", tag: "d10b61947cae275b7034f5259ba6fc28" },
        V { key: "9c7121289aefc67090cabed53ad11658be72a5372761b9d735e81d2bfc0e3267", iv: "ade1702d2051b8dd203b5419", pt: "b95bcaa2b31403d76859a4c301c50b56", aad: "", ct: "628285e6489090dde1b9a60674785003", tag: "9f516af3f3b93d610edbc5ba6e2d115f" },
        V { key: "0400b42897011fc20fd2280a52ef905d6ebf1b055b48c97067bd786d678ec4ea", iv: "0abfb0a41496b453358409d9", pt: "20c8230191e35f4e9b269d59cf5521f6", aad: "", ct: "dd8c38087daffbbb3ebb57ebf5ee5f78", tag: "bfb07aa5049ee350ec6fb1397f37087b" },
        V { key: "56690798978c154ff250ba78e463765f2f0ce69709a4551bd8cb3addeda087b6", iv: "cf37c286c18ad4ea3d0ba6a0", pt: "2d328124a8d58d56d0775eed93de1a88", aad: "", ct: "3b0a0267f6ecde3a78b30903ebd4ca6e", tag: "1fd2006409fc636379f3d4067eca0988" },
        V { key: "8a02a33bdf87e7845d7a8ae3c8727e704f4fd08c1f2083282d8cb3a5d3cedee9", iv: "599f5896851c968ed808323b", pt: "4ade8b32d56723fb8f65ce40825e27c9", aad: "", ct: "cb9133796b9075657840421a46022b63", tag: "a79e453c6fad8a5a4c2a8e87821c7f88" },
    ];

    #[test]
    fn nist_aes_gcm_256_encrypt_10_vectors() {
        for (i, v) in ENCRYPT.iter().enumerate() {
            let key  = to32(h(v.key));
            let iv   = to12(h(v.iv));
            let pt   = h(v.pt);
            let aad  = h(v.aad);
            let expected_ct  = h(v.ct);
            let expected_tag = h(v.tag);

            let result = aead_encrypt(&key, &pt, &iv, &aad);
            // aes-gcm appends 16-byte tag at end
            let ct_len = result.len() - 16;
            let (ct, tag) = result.split_at(ct_len);

            assert_eq!(ct, expected_ct.as_slice(),  "NIST AES-GCM vector {} CT mismatch", i);
            assert_eq!(tag, expected_tag.as_slice(), "NIST AES-GCM vector {} Tag mismatch", i);
        }
    }

    #[test]
    fn nist_aes_gcm_256_decrypt_10_vectors() {
        for (i, v) in ENCRYPT.iter().enumerate() {
            let key = to32(h(v.key));
            let iv  = to12(h(v.iv));
            let aad = h(v.aad);
            let pt  = h(v.pt);
            let mut ciphertext = h(v.ct);
            ciphertext.extend_from_slice(&h(v.tag));

            let result = aead_decrypt(&key, &ciphertext, &iv, &aad)
                .unwrap_or_else(|_| panic!("NIST AES-GCM vector {} decrypt failed", i));

            assert_eq!(result, pt, "NIST AES-GCM vector {} PT mismatch", i);
        }
    }

    #[test]
    fn nist_aes_gcm_tag_rejection() {
        // Tamper with tag — must return error
        let v = &ENCRYPT[0];
        let key = to32(h(v.key));
        let iv  = to12(h(v.iv));
        let aad = h(v.aad);
        let mut ciphertext = h(v.ct);
        let mut tag = h(v.tag);
        tag[0] ^= 0xff; // flip first byte
        ciphertext.extend_from_slice(&tag);

        assert!(
            aead_decrypt(&key, &ciphertext, &iv, &aad).is_err(),
            "Must reject tampered tag"
        );
    }
}

#[cfg(test)]
mod nist_hkdf {
    use crate::crypto::hkdf_sha256;

    fn h(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i+2], 16).unwrap())
            .collect()
    }

    // RFC 5869 Appendix A — official HKDF-SHA256 test vectors
    // (Referenced by NIST SP 800-56C Rev2)

    #[test]
    fn rfc5869_test_case_1() {
        // Hash = SHA-256, IKM len = 22, Salt len = 13, Info len = 10, L = 42
        let ikm  = h("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = h("000102030405060708090a0b0c");
        let info = h("f0f1f2f3f4f5f6f7f8f9");
        let expected = h("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
        let result = hkdf_sha256(&ikm, &salt, &info, 42);
        assert_eq!(result, expected, "RFC 5869 TC1 mismatch");
    }

    #[test]
    fn rfc5869_test_case_2() {
        // Hash = SHA-256, IKM len = 80, Salt len = 80, Info len = 80, L = 82
        // RFC 5869 Appendix A.2 exact values
        let ikm  = h("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f");
        let salt = h("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
        let info = h("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let expected = h("b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87");
        let result = hkdf_sha256(&ikm, &salt, &info, 82);
        assert_eq!(result, expected, "RFC 5869 TC2 mismatch");
    }

    #[test]
    fn rfc5869_test_case_3() {
        // Hash = SHA-256, no salt, no info, L = 42
        let ikm  = h("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = h(""); // empty → HKDF uses zeros
        let info = h("");
        let expected = h("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8");
        let result = hkdf_sha256(&ikm, &salt, &info, 42);
        assert_eq!(result, expected, "RFC 5869 TC3 mismatch");
    }
}
