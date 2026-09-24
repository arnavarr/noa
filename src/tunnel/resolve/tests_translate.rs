use crate::edge::model::{AddressTranslation, HostV1Config};

use super::testsupport::{fwd_ip_cfg, xlat};
use super::translate::{build_address_translations, translate_address};

// ----- T4b-2d-1: forwardAddressTranslations (`translateAddress` + the CIDR→CIDR renumber). -----
//
// The expected values below are a DIFFERENTIAL against `go 1.26.3`'s real `net/netip`: the oracle's
// `translateAddress`/`translateIP` were copied verbatim into a Go scratch and run, and every value
// here is the Go output. Covers every byte-math branch (full/partial/zero mask byte, /0../32, /1,
// /7, /16, /24, /31, /32, /64, /128), the longest-prefix-first sort, the Contains screen, the non-IP
// passthrough, and the out-of-range/cross-family edges. (See the worker's Go reference battery.)
#[test]
fn translate_v4_renumbers_host_bits_onto_to_network() {
    // /24: network from `to`, host bits (.7) from input. Go: 10.0.0.7 => 192.168.5.7.
    let xs = xlat(&[("10.0.0.0", "192.168.5.0", 24)]);
    assert_eq!(translate_address("10.0.0.7", &xs), "192.168.5.7");
}
#[test]
fn translate_v4_masks_host_bits_of_a_non_boundary_to() {
    // `to=1.2.3.4`/24 → `Masked()` zeros the low byte → 1.2.3.0; result 1.2.3.7. Go: 1.2.3.7.
    let xs = xlat(&[("10.0.0.0", "1.2.3.4", 24)]);
    assert_eq!(translate_address("10.0.0.7", &xs), "1.2.3.7");
}
#[test]
fn translate_v4_exact_host_route_32() {
    // /32: no host bits → result is `to`. Go: 192.168.1.4 => 1.2.3.4.
    let xs = xlat(&[("192.168.1.4", "1.2.3.4", 32)]);
    assert_eq!(translate_address("192.168.1.4", &xs), "1.2.3.4");
}
#[test]
fn translate_v4_prefix_zero_matches_all_yields_input() {
    // /0: every bit is host, `to` network is 0.0.0.0 → result == input. Go: 10.20.30.40 unchanged.
    let xs = xlat(&[("0.0.0.0", "9.9.9.9", 0)]);
    assert_eq!(translate_address("10.20.30.40", &xs), "10.20.30.40");
}
#[test]
fn translate_v4_partial_first_byte_slash7() {
    // /7: byte 0 is a partial mask (top 7 bits). Go: 11.2.3.4 (in 10.0.0.0/7) => 13.2.3.4.
    let xs = xlat(&[("10.0.0.0", "12.0.0.0", 7)]);
    assert_eq!(translate_address("11.2.3.4", &xs), "13.2.3.4");
    // /16 byte boundary: 172.16.99.88 => 10.5.99.88.
    let xs2 = xlat(&[("172.16.0.0", "10.5.0.0", 16)]);
    assert_eq!(translate_address("172.16.99.88", &xs2), "10.5.99.88");
    // /31 partial last byte: 10.0.0.1 => 192.168.5.1.
    let xs3 = xlat(&[("10.0.0.0", "192.168.5.0", 31)]);
    assert_eq!(translate_address("10.0.0.1", &xs3), "192.168.5.1");
}
#[test]
fn translate_no_matching_from_returns_unchanged() {
    // 11.0.0.7 is NOT in 10.0.0.0/24 → no match → unchanged. Go: unchanged.
    let xs = xlat(&[("10.0.0.0", "192.168.5.0", 24)]);
    assert_eq!(translate_address("11.0.0.7", &xs), "11.0.0.7");
}
#[test]
fn translate_longest_prefix_wins_via_desc_sort() {
    // Built /16-FIRST; the DESC sort must put /24 first so 192.168.1.55 (in BOTH) takes the /24.
    let xs = xlat(&[
        ("192.168.0.0", "10.0.0.0", 16),
        ("192.168.1.0", "1.2.3.0", 24),
    ]);
    assert_eq!(translate_address("192.168.1.55", &xs), "1.2.3.55"); // /24 wins
    // 192.168.2.55 is in ONLY the /16 → takes it. Go: 10.0.2.55.
    assert_eq!(translate_address("192.168.2.55", &xs), "10.0.2.55");
}
#[test]
fn translate_non_ip_address_is_returned_unchanged() {
    // A real hostname is not IP-parseable → returned verbatim (oracle `ParseAddr` err → `return addr`).
    let xs = xlat(&[("10.0.0.0", "192.168.5.0", 24)]);
    assert_eq!(translate_address("example.com", &xs), "example.com");
}
#[test]
fn translate_v6() {
    // /64: low 64 bits (host) preserved, high 64 from `to`. Go: 2001:db8::dead:beef => fd00:1::dead:beef.
    let xs = xlat(&[("2001:db8::", "fd00:1::", 64)]);
    assert_eq!(
        translate_address("2001:db8::dead:beef", &xs),
        "fd00:1::dead:beef"
    );
    // /128 exact. Go: => fd00::1.
    let xs2 = xlat(&[("2001:db8::1", "fd00::1", 128)]);
    assert_eq!(translate_address("2001:db8::1", &xs2), "fd00::1");
    // /1 partial first byte (top bit). Go: 4000::dead => c000::dead.
    let xs3 = xlat(&[("::", "8000::", 1)]);
    assert_eq!(translate_address("4000::dead", &xs3), "c000::dead");
}
#[test]
fn translate_out_of_range_prefix_is_inert_matching_go() {
    // Out-of-range prefix length: the oracle's `PrefixFrom` builds an INVALID prefix whose `Contains`
    // is always false → the translation is INERT (service still hosted, address unchanged). NOT a
    // startup error. Schema-unreachable (the controller caps /0-32 v4, /0-128 v6) but pinned to Go.
    let v4 = xlat(&[("10.0.0.0", "192.168.5.0", 33)]);
    assert_eq!(translate_address("10.0.0.7", &v4), "10.0.0.7");
    let v4big = xlat(&[("10.0.0.0", "192.168.5.0", 200)]);
    assert_eq!(translate_address("10.0.0.7", &v4big), "10.0.0.7");
    let v6 = xlat(&[("2001:db8::", "fd00::", 129)]);
    assert_eq!(translate_address("2001:db8::1", &v6), "2001:db8::1");
}
#[test]
fn translate_cross_family_is_inert_conscious_deviation() {
    // SCHEMA-UNREACHABLE (the `addressTranslation` `oneOf` forces same-family from/to). Go would
    // byte-renumber a v4-`from`/v6-`to` (its `translateIP` slices the v6 `to`'s first 4 bytes →
    // `253.0.0.7`); we instead skip it → the address is dialed UNCHANGED (the allow-listed original),
    // never a byte-soup target. Documented safe-direction deviation in [`translate_ip`].
    let xs = xlat(&[("10.0.0.0", "fd00::", 24)]);
    assert_eq!(translate_address("10.0.0.7", &xs), "10.0.0.7");
}
#[test]
fn translate_v4_mapped_input_is_not_contained_by_a_v4_prefix() {
    // `::ffff:10.0.0.7` parses to `IpAddr::V6` → a v4 prefix does not contain it (oracle `Contains`
    // agrees: a v6-mapped address is not in a v4 prefix). Unchanged. Go: unchanged.
    let xs = xlat(&[("10.0.0.0", "192.168.5.0", 24)]);
    assert_eq!(translate_address("::ffff:10.0.0.7", &xs), "::ffff:10.0.0.7");
}
#[test]
fn translate_with_no_translations_is_a_noop() {
    assert_eq!(translate_address("10.0.0.7", &[]), "10.0.0.7");
}
#[test]
fn build_address_translations_fails_loud_on_bad_from_or_to() {
    // Bad `from`/`to` → the oracle `log.Errorf + return nil` (service not hosted). We fail loud at
    // startup with a clear operator-facing reason. A leading-zero IPv4 (`010.0.0.0`) is rejected by
    // `netip.ParseAddr` (the strict-parse stance from T4b-2a) → mirrors the oracle.
    let mut cfg = fwd_ip_cfg();
    cfg.forward_address_translations = vec![AddressTranslation {
        from: "010.0.0.0".to_string(),
        to: "1.2.3.0".to_string(),
        prefix_length: 24,
    }];
    assert_eq!(
        build_address_translations(&cfg).unwrap_err(),
        "failed to parse 'from' address translation '010.0.0.0'"
    );
    cfg.forward_address_translations = vec![AddressTranslation {
        from: "1.2.3.0".to_string(),
        to: "not-an-ip".to_string(),
        prefix_length: 24,
    }];
    assert_eq!(
        build_address_translations(&cfg).unwrap_err(),
        "failed to parse 'to' address translation 'not-an-ip'"
    );
}
#[test]
fn build_address_translations_ignores_translations_when_not_forwarding_address() {
    // The oracle only builds translations under `if config.ForwardAddress` (hosting.go:76). A
    // `forwardAddress:false` config with a stray translation → IGNORED (empty), NOT rejected — even a
    // malformed one (never parsed). Deliberate behavior change vs T4b-1/2c (which rejected it).
    let mut cfg = HostV1Config {
        forward_address: false,
        ..fwd_ip_cfg()
    };
    cfg.forward_address_translations = vec![AddressTranslation {
        from: "garbage".to_string(),
        to: "garbage".to_string(),
        prefix_length: 99,
    }];
    assert_eq!(build_address_translations(&cfg).unwrap(), vec![]);
    // And an empty translations list under forwardAddress → empty.
    assert_eq!(build_address_translations(&fwd_ip_cfg()).unwrap(), vec![]);
}
/// BROAD DIFFERENTIAL (the arc's gold standard, T4b-1/2a/2c lesson): 60 RANDOM `(from, to, prefix,
/// input, expected)` cases — 40 v4 (prefix 0-32) + 20 v6 (prefix 0-128) — generated by running the
/// oracle's `translateAddress`/`translateIP` verbatim against `go 1.26.3 net/netip` (seed 42). Half the
/// inputs are forced inside the `from` prefix (exercise the renumber), half are random (exercise the
/// Contains miss → unchanged). Pins our port byte-for-byte to Go incl. the canonical `to_string()`.
#[test]
#[allow(clippy::too_many_lines)] // a 60-row differential vector table, not real logic
fn translate_matches_go_random_battery() {
    // (from, to, prefix, input, expected) — every `expected` is a `go net/netip` output.
    let cases: &[(&str, &str, u8, &str, &str)] = &[
        (
            "83.140.127.150",
            "177.100.191.27",
            23,
            "83.140.127.75",
            "177.100.191.75",
        ),
        (
            "180.114.9.221",
            "157.82.223.215",
            13,
            "155.192.214.20",
            "155.192.214.20",
        ),
        (
            "76.136.133.53",
            "132.26.203.224",
            13,
            "112.155.7.225",
            "112.155.7.225",
        ),
        (
            "143.218.158.111",
            "130.229.78.116",
            28,
            "143.218.158.110",
            "130.229.78.126",
        ),
        (
            "75.28.235.234",
            "84.109.143.172",
            17,
            "199.142.27.11",
            "199.142.27.11",
        ),
        (
            "175.174.136.27",
            "130.167.81.16",
            31,
            "175.174.136.26",
            "130.167.81.16",
        ),
        (
            "227.198.196.243",
            "174.123.195.224",
            28,
            "73.91.87.18",
            "73.91.87.18",
        ),
        (
            "105.44.182.7",
            "218.0.161.28",
            16,
            "28.112.113.231",
            "28.112.113.231",
        ),
        (
            "150.162.201.35",
            "38.130.142.43",
            5,
            "5.14.212.193",
            "5.14.212.193",
        ),
        (
            "22.2.63.168",
            "227.87.107.111",
            19,
            "22.2.63.56",
            "227.87.127.56",
        ),
        (
            "150.77.253.199",
            "158.141.83.67",
            32,
            "115.102.28.253",
            "115.102.28.253",
        ),
        (
            "102.98.144.207",
            "43.235.66.195",
            23,
            "102.98.145.70",
            "43.235.67.70",
        ),
        (
            "128.64.44.95",
            "178.130.14.136",
            24,
            "128.64.44.70",
            "178.130.14.70",
        ),
        (
            "227.237.77.166",
            "70.169.174.139",
            7,
            "227.167.180.252",
            "71.167.180.252",
        ),
        (
            "241.207.210.179",
            "181.18.25.234",
            14,
            "241.207.58.191",
            "181.19.58.191",
        ),
        (
            "68.141.157.163",
            "158.14.146.157",
            12,
            "68.129.133.77",
            "158.1.133.77",
        ),
        (
            "235.95.228.36",
            "254.247.172.33",
            6,
            "8.145.245.235",
            "8.145.245.235",
        ),
        (
            "231.44.39.160",
            "152.192.33.151",
            31,
            "231.44.39.160",
            "152.192.33.150",
        ),
        (
            "195.231.226.23",
            "72.48.63.244",
            10,
            "167.152.188.100",
            "167.152.188.100",
        ),
        (
            "222.14.93.178",
            "134.75.42.211",
            24,
            "194.108.195.70",
            "194.108.195.70",
        ),
        (
            "94.41.160.220",
            "164.106.195.160",
            2,
            "85.112.19.59",
            "149.112.19.59",
        ),
        (
            "25.74.225.186",
            "159.42.131.134",
            9,
            "174.114.179.102",
            "174.114.179.102",
        ),
        (
            "31.232.124.153",
            "194.184.125.109",
            7,
            "30.134.244.87",
            "194.134.244.87",
        ),
        (
            "146.30.195.124",
            "14.70.12.240",
            23,
            "215.3.208.171",
            "215.3.208.171",
        ),
        (
            "215.186.101.34",
            "76.162.105.120",
            23,
            "217.165.206.98",
            "217.165.206.98",
        ),
        (
            "254.156.24.60",
            "25.51.169.22",
            18,
            "215.56.59.153",
            "215.56.59.153",
        ),
        (
            "60.105.73.153",
            "69.176.176.207",
            5,
            "59.220.194.158",
            "67.220.194.158",
        ),
        (
            "68.47.14.49",
            "194.201.83.150",
            9,
            "96.240.95.179",
            "96.240.95.179",
        ),
        (
            "0.65.111.166",
            "22.149.185.32",
            3,
            "46.104.54.58",
            "46.104.54.58",
        ),
        (
            "28.120.124.129",
            "31.189.136.91",
            28,
            "28.120.124.129",
            "31.189.136.81",
        ),
        (
            "214.39.140.159",
            "124.135.47.132",
            23,
            "15.157.148.43",
            "15.157.148.43",
        ),
        (
            "236.198.170.118",
            "195.176.249.72",
            16,
            "175.190.97.39",
            "175.190.97.39",
        ),
        (
            "165.247.104.100",
            "236.42.224.205",
            18,
            "165.247.69.10",
            "236.42.197.10",
        ),
        (
            "182.25.158.199",
            "179.150.214.24",
            1,
            "253.224.186.92",
            "253.224.186.92",
        ),
        (
            "108.212.253.77",
            "57.44.146.180",
            24,
            "108.212.253.18",
            "57.44.146.18",
        ),
        (
            "41.25.194.168",
            "122.73.148.252",
            20,
            "30.64.30.17",
            "30.64.30.17",
        ),
        (
            "197.164.66.236",
            "61.62.246.13",
            23,
            "182.201.243.61",
            "182.201.243.61",
        ),
        (
            "177.62.209.247",
            "174.27.227.132",
            17,
            "19.35.40.193",
            "19.35.40.193",
        ),
        (
            "112.137.232.243",
            "38.122.12.204",
            26,
            "126.57.191.202",
            "126.57.191.202",
        ),
        (
            "199.70.184.25",
            "22.174.70.255",
            6,
            "102.123.46.180",
            "102.123.46.180",
        ),
        (
            "1a40:117:556f:e5cb:405b:3170:acac:a5c7",
            "5baf:7f7b:70e8:6144:d3ba:36b:3b1f:58fe",
            64,
            "1a40:117:556f:e5cb:6cf2:ca6c:46ed:8816",
            "5baf:7f7b:70e8:6144:6cf2:ca6c:46ed:8816",
        ),
        (
            "2f5d:45cd:b5a0:763a:e7e1:833f:b7ad:f989",
            "36f5:1e4d:da8a:284e:f19a:85bb:8743:7b41",
            81,
            "2f5d:45cd:b5a0:763a:e7e1:bf30:c50b:679d",
            "36f5:1e4d:da8a:284e:f19a:bf30:c50b:679d",
        ),
        (
            "5056:8955:c9c1:9808:9d95:f603:97d2:af5f",
            "8fc9:110b:e3a9:e125:e944:8497:9708:d6aa",
            120,
            "7c86:873a:1ead:5a4:a667:1d69:515c:839d",
            "7c86:873a:1ead:5a4:a667:1d69:515c:839d",
        ),
        (
            "d8af:3a3a:d774:2c5:fd3a:83a0:4608:a989",
            "3300:2162:dd4c:1ff5:547f:5752:31f:2121",
            63,
            "e141:61ea:e9b6:52df:3300:b4c2:ab58:2776",
            "e141:61ea:e9b6:52df:3300:b4c2:ab58:2776",
        ),
        (
            "d85b:68ca:32d5:c373:c264:7858:3bc4:8fa3",
            "6be4:8d65:9c3f:e173:4101:c7e4:8fd3:7fb9",
            122,
            "fae3:f0d2:c89e:a4d6:5d76:60e:6487:9059",
            "fae3:f0d2:c89e:a4d6:5d76:60e:6487:9059",
        ),
        (
            "324b:b75a:db14:1a2f:7c2f:de78:11f4:81cf",
            "86a:3ec3:d8b3:7700:12fd:27a4:b65b:2ae",
            20,
            "8525:6f73:2f72:695a:570d:bf26:47f2:95e2",
            "8525:6f73:2f72:695a:570d:bf26:47f2:95e2",
        ),
        (
            "3395:eeda:cff6:36e1:b0cf:20de:6a10:ff99",
            "43ed:ca6f:96bf:4dda:f00b:9d4f:cd6a:cbdb",
            28,
            "b3f6:3194:50f2:ba23:dca6:67df:a655:134c",
            "b3f6:3194:50f2:ba23:dca6:67df:a655:134c",
        ),
        (
            "594a:2c80:6bdf:a4e7:56e4:58b4:8bae:490d",
            "42e:7a3:55e9:6cfb:89cc:abf2:819d:794d",
            53,
            "9e12:82fd:a72:d350:8a69:380b:a60d:5ff4",
            "9e12:82fd:a72:d350:8a69:380b:a60d:5ff4",
        ),
        (
            "b432:7bf6:50e0:131b:8f57:75ad:8697:a734",
            "63cd:2806:e6ae:eef9:2b5e:9bff:e40e:9466",
            125,
            "d295:13d3:1ed4:ff1d:16e6:d599:5619:515f",
            "d295:13d3:1ed4:ff1d:16e6:d599:5619:515f",
        ),
        (
            "5f53:8769:ed:f7a:d1f2:38bb:3344:9e3",
            "c164:9573:a56f:43a8:e1d2:1372:46fc:a6c6",
            29,
            "331e:2432:3d80:e7cb:845f:43d2:2322:9aa4",
            "331e:2432:3d80:e7cb:845f:43d2:2322:9aa4",
        ),
        (
            "2114:4a27:dbb7:c440:c1c7:98f9:a24d:2c85",
            "f12c:2488:bf87:d2d9:29a0:a479:a55b:7b73",
            101,
            "e4ef:fe83:2163:7598:26df:39f8:3369:5ca2",
            "e4ef:fe83:2163:7598:26df:39f8:3369:5ca2",
        ),
        (
            "2aa6:5195:4890:bcdc:cf66:ad3d:73a8:e1ab",
            "9f83:877d:263b:bb27:f5bc:497b:d654:474d",
            38,
            "2aa6:5195:481c:e4ae:769d:ddb6:21c1:6432",
            "9f83:877d:241c:e4ae:769d:ddb6:21c1:6432",
        ),
        (
            "39bd:378a:2e91:a9ac:e277:f2c0:8d71:4bc9",
            "d9e6:2c05:62ca:296e:12a7:7617:44dd:b823",
            88,
            "39bd:378a:2e91:a9ac:e277:f230:ecf2:5fa6",
            "d9e6:2c05:62ca:296e:12a7:7630:ecf2:5fa6",
        ),
        (
            "66c9:246b:81d:5d2c:578e:ef00:8b0:8d61",
            "a097:6404:f42e:a82a:4873:fb0d:6487:777d",
            59,
            "66c9:246b:81d:5d24:c2e3:bfac:e0e6:30b",
            "a097:6404:f42e:a824:c2e3:bfac:e0e6:30b",
        ),
        (
            "7c00:69b9:7c69:c98:34c2:2829:ba9b:d4ff",
            "a9af:5819:6f77:5e30:f3c9:3b49:ec2f:1e8a",
            23,
            "37e4:4888:77ff:7a6b:bcac:e3ee:a01b:d759",
            "37e4:4888:77ff:7a6b:bcac:e3ee:a01b:d759",
        ),
        (
            "400d:87b9:80b3:53c1:15cb:c162:a778:dd9e",
            "a042:359d:4c20:fe21:8a46:6fdc:aa07:f345",
            116,
            "ea9c:fcc6:58f2:edb1:2492:9cdc:cf58:8f49",
            "ea9c:fcc6:58f2:edb1:2492:9cdc:cf58:8f49",
        ),
        (
            "4ebe:3346:c19a:ed78:7b97:c577:dfe:de84",
            "5cf5:b040:dcb6:894:4866:3fc3:3217:c1f2",
            35,
            "2f93:43e4:3e5e:94fc:a5e4:847:46d:f9d8",
            "2f93:43e4:3e5e:94fc:a5e4:847:46d:f9d8",
        ),
        (
            "8802:be24:12a1:3467:b665:562f:3287:48e4",
            "83c5:ea98:5123:cc42:2e4f:7a8c:e974:753",
            51,
            "8802:be24:12a1:2c2b:7ca2:ca0d:8a20:2325",
            "83c5:ea98:5123:cc2b:7ca2:ca0d:8a20:2325",
        ),
        (
            "c7b8:cb6:35e8:5dbd:2337:40d5:9378:a212",
            "953b:7917:cc7f:45d6:ec01:4d1f:b59:d68",
            113,
            "b451:3319:5191:e318:d0f3:49f3:8225:1de0",
            "b451:3319:5191:e318:d0f3:49f3:8225:1de0",
        ),
        (
            "3b35:f57d:cf52:b968:260a:945c:919c:8fb9",
            "fb8d:fa84:7d66:fba0:234a:dbbc:36e3:46a4",
            124,
            "3b35:f57d:cf52:b968:260a:945c:919c:8fbd",
            "fb8d:fa84:7d66:fba0:234a:dbbc:36e3:46ad",
        ),
    ];
    for (from, to, prefix, input, expected) in cases {
        let xs = xlat(&[(from, to, *prefix)]);
        assert_eq!(
            &translate_address(input, &xs),
            expected,
            "translate({input}) with {from}->{to}/{prefix}"
        );
    }
}
