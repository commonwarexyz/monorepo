#![no_main]

use arbitrary::Arbitrary;
use commonware_utils::net::{IpAddrExt, SubnetMask};
use libfuzzer_sys::fuzz_target;
use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

#[derive(Arbitrary, Debug)]
enum FuzzInput {
    SubnetMaskCreate {
        ipv4_bits: u8,
        ipv6_bits: u8,
    },
    SubnetMaskApplyV4 {
        ipv4_bits: u8,
        ipv6_bits: u8,
        octets: [u8; 4],
    },
    SubnetMaskApplyV6 {
        ipv4_bits: u8,
        ipv6_bits: u8,
        segments: [u16; 8],
    },
    IpAddrSubnetV4 {
        octets: [u8; 4],
        ipv4_bits: u8,
        ipv6_bits: u8,
    },
    IpAddrSubnetV6 {
        segments: [u16; 8],
        ipv4_bits: u8,
        ipv6_bits: u8,
    },
    IpAddrGlobalV4 {
        octets: [u8; 4],
    },
    IpAddrGlobalV6 {
        segments: [u16; 8],
    },
    SubnetOperationsV4 {
        octets1: [u8; 4],
        octets2: [u8; 4],
        ipv4_bits: u8,
        ipv6_bits: u8,
    },
    SubnetOperationsV6 {
        segments1: [u16; 8],
        segments2: [u16; 8],
        ipv4_bits: u8,
        ipv6_bits: u8,
    },
}

fn fuzz(input: FuzzInput) {
    match input {
        FuzzInput::SubnetMaskCreate {
            ipv4_bits,
            ipv6_bits,
        } => {
            let mask = SubnetMask::new(ipv4_bits, ipv6_bits);
            // Bits above the address width are clamped on construction.
            let v4_capped = (ipv4_bits as u32).min(32);
            let v6_capped = (ipv6_bits as u32).min(128);
            let expected_v4 = if v4_capped == 0 {
                0
            } else {
                (!0u32) << (32 - v4_capped)
            };
            let expected_v6 = if v6_capped == 0 {
                0
            } else {
                (!0u128) << (128 - v6_capped)
            };
            assert_eq!(mask.ipv4, expected_v4);
            assert_eq!(mask.ipv6, expected_v6);
        }

        FuzzInput::SubnetMaskApplyV4 {
            ipv4_bits,
            ipv6_bits,
            octets,
        } => {
            let mask = SubnetMask::new(ipv4_bits, ipv6_bits);
            let addr = IpAddr::V4(Ipv4Addr::from(octets));
            // Idempotence: subnet of an already-masked address equals subnet
            // of the original. Encoded by re-applying subnet to the manually
            // masked address.
            let masked = IpAddr::V4(Ipv4Addr::from(
                u32::from(Ipv4Addr::from(octets)) & mask.ipv4,
            ));
            assert_eq!(addr.subnet(&mask), masked.subnet(&mask));
        }

        FuzzInput::SubnetMaskApplyV6 {
            ipv4_bits,
            ipv6_bits,
            segments,
        } => {
            let mask = SubnetMask::new(ipv4_bits, ipv6_bits);
            let v6 = Ipv6Addr::from(segments);
            let addr = IpAddr::V6(v6);
            // Idempotence: subnet must agree on the original and the manually
            // masked address. IPv4-mapped form switches to IPv4 masking, so
            // mirror that branch.
            let masked = if let Some(v4) = v6.to_ipv4_mapped() {
                IpAddr::V4(Ipv4Addr::from(u32::from(v4) & mask.ipv4))
            } else {
                IpAddr::V6(Ipv6Addr::from(u128::from(v6) & mask.ipv6))
            };
            assert_eq!(addr.subnet(&mask), masked.subnet(&mask));
        }

        FuzzInput::IpAddrSubnetV4 {
            octets,
            ipv4_bits,
            ipv6_bits,
        } => {
            let addr = IpAddr::V4(Ipv4Addr::from(octets));
            let mask = SubnetMask::new(ipv4_bits, ipv6_bits);
            // IPv4-mapped IPv6 of the same v4 address must produce the same
            // subnet as the IPv4 address itself.
            let v6_mapped = IpAddr::V6(Ipv4Addr::from(octets).to_ipv6_mapped());
            assert_eq!(addr.subnet(&mask), v6_mapped.subnet(&mask));
        }

        FuzzInput::IpAddrSubnetV6 {
            segments,
            ipv4_bits,
            ipv6_bits,
        } => {
            let addr = IpAddr::V6(Ipv6Addr::from(segments));
            let mask = SubnetMask::new(ipv4_bits, ipv6_bits);
            // Subnet is deterministic: calling twice with the same inputs
            // returns equal Subnets.
            assert_eq!(addr.subnet(&mask), addr.subnet(&mask));
        }

        FuzzInput::IpAddrGlobalV4 { octets } => {
            let addr = IpAddr::V4(Ipv4Addr::from(octets));
            // is_global is deterministic.
            assert_eq!(IpAddrExt::is_global(&addr), IpAddrExt::is_global(&addr));
            // 127.0.0.0/8 is loopback and never global.
            if octets[0] == 127 {
                assert!(addr.is_loopback());
                assert!(!IpAddrExt::is_global(&addr));
            }
            // 255.255.255.255 is broadcast and never global.
            if octets == [255, 255, 255, 255] {
                assert!(!IpAddrExt::is_global(&addr));
            }
        }

        FuzzInput::IpAddrGlobalV6 { segments } => {
            let addr = IpAddr::V6(Ipv6Addr::from(segments));
            assert_eq!(IpAddrExt::is_global(&addr), IpAddrExt::is_global(&addr));
            // ::1 is loopback and never global.
            if segments == [0, 0, 0, 0, 0, 0, 0, 1] {
                assert!(addr.is_loopback());
                assert!(!IpAddrExt::is_global(&addr));
            }
        }

        FuzzInput::SubnetOperationsV4 {
            octets1,
            octets2,
            ipv4_bits,
            ipv6_bits,
        } => {
            let addr1 = IpAddr::V4(Ipv4Addr::from(octets1));
            let addr2 = IpAddr::V4(Ipv4Addr::from(octets2));
            let mask = SubnetMask::new(ipv4_bits, ipv6_bits);

            let subnet1 = addr1.subnet(&mask);
            let subnet2 = addr2.subnet(&mask);

            // Same masked prefix iff equal subnets.
            let prefix1 = u32::from(Ipv4Addr::from(octets1)) & mask.ipv4;
            let prefix2 = u32::from(Ipv4Addr::from(octets2)) & mask.ipv4;
            assert_eq!(prefix1 == prefix2, subnet1 == subnet2);

            // Equal subnets must hash to the same value.
            if subnet1 == subnet2 {
                let mut h1 = DefaultHasher::new();
                let mut h2 = DefaultHasher::new();
                subnet1.hash(&mut h1);
                subnet2.hash(&mut h2);
                assert_eq!(h1.finish(), h2.finish());
            }
        }

        FuzzInput::SubnetOperationsV6 {
            segments1,
            segments2,
            ipv4_bits,
            ipv6_bits,
        } => {
            let v6_1 = Ipv6Addr::from(segments1);
            let v6_2 = Ipv6Addr::from(segments2);
            let addr1 = IpAddr::V6(v6_1);
            let addr2 = IpAddr::V6(v6_2);
            let mask = SubnetMask::new(ipv4_bits, ipv6_bits);

            let subnet1 = addr1.subnet(&mask);
            let subnet2 = addr2.subnet(&mask);

            // Same-prefix invariant only holds when neither is an IPv4-mapped
            // form (which silently switches to IPv4 masking).
            if v6_1.to_ipv4_mapped().is_none() && v6_2.to_ipv4_mapped().is_none() {
                let prefix1 = u128::from(v6_1) & mask.ipv6;
                let prefix2 = u128::from(v6_2) & mask.ipv6;
                assert_eq!(prefix1 == prefix2, subnet1 == subnet2);
            }

            // Equal subnets must hash to the same value.
            if subnet1 == subnet2 {
                let mut h1 = DefaultHasher::new();
                let mut h2 = DefaultHasher::new();
                subnet1.hash(&mut h1);
                subnet2.hash(&mut h2);
                assert_eq!(h1.finish(), h2.finish());
            }
        }
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
