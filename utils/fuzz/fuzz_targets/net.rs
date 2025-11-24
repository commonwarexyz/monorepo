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
            let _ = SubnetMask::new(ipv4_bits, ipv6_bits);
        }

        FuzzInput::SubnetMaskApplyV4 {
            ipv4_bits,
            ipv6_bits,
            octets,
        } => {
            let mask = SubnetMask::new(ipv4_bits, ipv6_bits);
            let addr = IpAddr::V4(Ipv4Addr::from(octets));
            let _ = addr.subnet(&mask);
        }

        FuzzInput::SubnetMaskApplyV6 {
            ipv4_bits,
            ipv6_bits,
            segments,
        } => {
            let mask = SubnetMask::new(ipv4_bits, ipv6_bits);
            let addr = IpAddr::V6(Ipv6Addr::from(segments));
            let _ = addr.subnet(&mask);
        }

        FuzzInput::IpAddrSubnetV4 {
            octets,
            ipv4_bits,
            ipv6_bits,
        } => {
            let addr = IpAddr::V4(Ipv4Addr::from(octets));
            let mask = SubnetMask::new(ipv4_bits, ipv6_bits);
            let subnet = addr.subnet(&mask);
            let _ = format!("{:?}", subnet);
        }

        FuzzInput::IpAddrSubnetV6 {
            segments,
            ipv4_bits,
            ipv6_bits,
        } => {
            let addr = IpAddr::V6(Ipv6Addr::from(segments));
            let mask = SubnetMask::new(ipv4_bits, ipv6_bits);
            let subnet = addr.subnet(&mask);
            let _ = format!("{:?}", subnet);
        }

        FuzzInput::IpAddrGlobalV4 { octets } => {
            let addr = IpAddr::V4(Ipv4Addr::from(octets));
            let _ = IpAddrExt::is_global(&addr);
            let _ = addr.is_loopback();
        }

        FuzzInput::IpAddrGlobalV6 { segments } => {
            let addr = IpAddr::V6(Ipv6Addr::from(segments));
            let _ = IpAddrExt::is_global(&addr);
            let _ = addr.is_loopback();
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

            let _ = subnet1 == subnet2;
            let _ = subnet1 != subnet2;

            let mut hasher = DefaultHasher::new();
            subnet1.hash(&mut hasher);
            let _ = hasher.finish();

            let _ = format!("{:?}", subnet1);
        }

        FuzzInput::SubnetOperationsV6 {
            segments1,
            segments2,
            ipv4_bits,
            ipv6_bits,
        } => {
            let addr1 = IpAddr::V6(Ipv6Addr::from(segments1));
            let addr2 = IpAddr::V6(Ipv6Addr::from(segments2));
            let mask = SubnetMask::new(ipv4_bits, ipv6_bits);

            let subnet1 = addr1.subnet(&mask);
            let subnet2 = addr2.subnet(&mask);

            let _ = subnet1 == subnet2;
            let _ = subnet1 != subnet2;

            let mut hasher = DefaultHasher::new();
            subnet1.hash(&mut hasher);
            let _ = hasher.finish();

            let _ = format!("{:?}", subnet1);
        }
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
