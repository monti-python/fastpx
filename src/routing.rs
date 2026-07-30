use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::IpCidr;

pub(crate) fn is_direct_address(address: IpAddr, additional: &[IpCidr]) -> bool {
    is_default_direct_address(address) || additional.iter().any(|network| network.contains(address))
}

fn is_default_direct_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_default_direct_v4(address),
        IpAddr::V6(address) => is_default_direct_v6(address),
    }
}

fn is_default_direct_v4(address: Ipv4Addr) -> bool {
    let [first, second, ..] = address.octets();
    address.is_loopback()
        || address.is_private()
        || address.is_link_local()
        || (first == 100 && (64..=127).contains(&second))
}

fn is_default_direct_v6(address: Ipv6Addr) -> bool {
    let first = address.octets()[0];
    address.is_loopback() || address.is_unicast_link_local() || first & 0xfe == 0xfc
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::is_direct_address;
    use crate::IpCidr;

    #[test]
    fn recognizes_internal_address_ranges() {
        for address in [
            "127.0.0.1",
            "10.1.2.3",
            "172.31.255.254",
            "192.168.4.5",
            "169.254.10.20",
            "100.64.0.1",
            "::1",
            "fe80::1",
            "fd12:3456::1",
        ] {
            assert!(
                is_direct_address(address.parse::<IpAddr>().unwrap(), &[]),
                "{address}"
            );
        }
    }

    #[test]
    fn public_addresses_use_the_proxy_by_default() {
        for address in ["1.1.1.1", "8.8.8.8", "172.32.0.1", "2001:4860:4860::8888"] {
            assert!(
                !is_direct_address(address.parse::<IpAddr>().unwrap(), &[]),
                "{address}"
            );
        }
    }

    #[test]
    fn additional_networks_are_direct() {
        let networks = ["203.0.113.0/24".parse::<IpCidr>().unwrap()];
        assert!(is_direct_address(
            "203.0.113.42".parse::<IpAddr>().unwrap(),
            &networks
        ));
    }
}
