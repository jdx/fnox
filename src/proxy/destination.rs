//! Which addresses the proxy may connect to: public addresses, plus the
//! networks `allow_private` names.

use super::*;

/// Address ranges that are not reachable on the public internet: loopback,
/// private, link-local (which holds cloud metadata endpoints), shared, and
/// reserved space. IPv4-mapped IPv6 addresses are canonicalized before this
/// check, and NAT64 and 6to4 addresses are checked by their embedded IPv4.
pub(super) static NON_PUBLIC_NETWORKS: LazyLock<Vec<IpNet>> = LazyLock::new(|| {
    [
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/3",
        "::/96",
        "64:ff9b:1::/48",
        "100::/64",
        "2001:2::/48",
        "2001:db8::/32",
        "3fff::/20",
        "fc00::/7",
        "fe80::/10",
        "fec0::/10",
        "ff00::/8",
    ]
    .into_iter()
    .map(|network| network.parse().expect("static network is valid"))
    .collect()
});

pub(super) fn is_public(ip: IpAddr) -> bool {
    let ip = ip.to_canonical();
    if let IpAddr::V6(v6) = ip
        && let Some(embedded) = embedded_ipv4(v6)
    {
        return is_public(IpAddr::V4(embedded));
    }
    !NON_PUBLIC_NETWORKS
        .iter()
        .any(|network| network.contains(&ip))
}

/// The IPv4 address a NAT64 (`64:ff9b::/96`) or 6to4 (`2002::/16`) address
/// reaches.
pub(super) fn embedded_ipv4(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    let segments = ip.segments();
    let octets = ip.octets();
    if segments[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        Some(Ipv4Addr::new(
            octets[12], octets[13], octets[14], octets[15],
        ))
    } else if segments[0] == 0x2002 {
        Some(Ipv4Addr::new(octets[2], octets[3], octets[4], octets[5]))
    } else {
        None
    }
}

/// Which resolved addresses the proxy may connect to.
#[derive(Debug, Default)]
pub(super) struct DestinationPolicy {
    pub(super) allowed: Vec<IpNet>,
}

#[derive(Debug)]
pub(super) enum DestinationError {
    Lookup(std::io::Error),
    /// Every address the name resolved to is non-public and not allowed.
    Refused,
}

impl std::fmt::Display for DestinationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Lookup(error) => write!(f, "failed to resolve destination: {error}"),
            Self::Refused => f.write_str("destination resolves to a non-public address"),
        }
    }
}

impl std::error::Error for DestinationError {}

impl DestinationPolicy {
    pub(super) fn permits(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        is_public(ip) || self.allowed.iter().any(|network| network.contains(&ip))
    }

    /// Resolves `host` and keeps only addresses the proxy may connect to.
    /// Callers connect to these addresses, never to the name again, so a
    /// second lookup cannot rebind it to a refused address.
    pub(super) async fn resolve(
        &self,
        host: &str,
        port: u16,
    ) -> std::result::Result<Vec<SocketAddr>, DestinationError> {
        let resolved: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
            .await
            .map_err(DestinationError::Lookup)?
            .collect();
        if resolved.is_empty() {
            return Err(DestinationError::Lookup(std::io::Error::other(
                "no addresses found",
            )));
        }
        let permitted: Vec<_> = resolved
            .into_iter()
            .filter(|address| self.permits(address.ip()))
            .collect();
        if permitted.is_empty() {
            return Err(DestinationError::Refused);
        }
        Ok(permitted)
    }
}

/// Applies the destination policy to the upstream client's own lookups.
pub(super) struct DestinationResolver(pub(super) Arc<DestinationPolicy>);

impl reqwest::dns::Resolve for DestinationResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let destinations = self.0.clone();
        let host = name.as_str().to_string();
        Box::pin(async move {
            let addresses = destinations.resolve(&host, 0).await?;
            Ok(Box::new(addresses.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

pub(super) fn parse_network(entry: &str) -> Result<IpNet> {
    entry
        .parse::<IpNet>()
        .or_else(|_| entry.parse::<IpAddr>().map(IpNet::from))
        .map(|network| canonical_network(network.trunc()))
        .map_err(|_| {
            proxy_error(format!(
                "allow_private entry '{entry}' is not an IP address or CIDR block"
            ))
        })
}

/// Rewrites an IPv4-mapped IPv6 network (`::ffff:a.b.c.d/96+n`) as the IPv4
/// network it covers, since destinations are canonicalized the same way
/// before they are checked against the allow list.
pub(super) fn canonical_network(network: IpNet) -> IpNet {
    if let IpNet::V6(v6) = network
        && v6.prefix_len() >= 96
        && let Some(v4) = v6.addr().to_ipv4_mapped()
    {
        return IpNet::V4(
            ipnet::Ipv4Net::new(v4, v6.prefix_len() - 96).expect("a prefix of 32 or less is valid"),
        );
    }
    network
}
