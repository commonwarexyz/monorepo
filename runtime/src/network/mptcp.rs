//! Stream socket creation with optional Multipath TCP (MPTCP) on Linux.
//!
//! MPTCP is best effort. Socket creation falls back to TCP only when the kernel
//! reports MPTCP as unsupported or disabled, and returns every other error. After
//! creation, the kernel negotiates MPTCP with the peer and continues as TCP when
//! the peer or path does not support it.

use std::{
    io,
    net::SocketAddr,
    os::fd::{FromRawFd as _, OwnedFd},
};
use tracing::debug;

/// Create an unconnected, nonblocking, close-on-exec stream socket for the
/// family of `address`, using MPTCP when `mptcp` is set and the kernel supports it.
pub(crate) fn socket(address: SocketAddr, mptcp: bool) -> io::Result<OwnedFd> {
    let family = if address.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };
    if mptcp {
        match create(family, libc::IPPROTO_MPTCP) {
            Err(err) if unavailable(&err) => debug!(?err, "MPTCP unavailable, using TCP"),
            result => return result,
        }
    }
    create(family, 0)
}

/// Create a nonblocking, close-on-exec stream socket with `protocol`.
fn create(family: libc::c_int, protocol: libc::c_int) -> io::Result<OwnedFd> {
    // SAFETY: socket takes only integer arguments and returns a fresh descriptor
    // or -1. The successful descriptor is immediately placed in one owner.
    let raw = unsafe {
        libc::socket(
            family,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            protocol,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: `raw` is the unique successful result of socket above and has not
    // been closed or placed in another owning descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

/// Returns whether a socket creation error reports MPTCP as unavailable.
///
/// Linux reports `ENOPROTOOPT` when `net.mptcp.enabled` is 0, `EPROTONOSUPPORT`
/// when MPTCP is not built into a 5.6 or newer kernel, and `EINVAL` for the
/// unknown protocol on older kernels (the other arguments are always valid).
/// Permission, resource, and other errors do not indicate missing support.
fn unavailable(err: &io::Error) -> bool {
    matches!(
        err.raw_os_error(),
        Some(libc::ENOPROTOOPT | libc::EPROTONOSUPPORT | libc::EINVAL)
    )
}

#[cfg(test)]
pub(crate) mod tests {
    //! Linux MPTCP introspection and disposable network namespaces for tests.

    use super::*;
    use std::{
        fs::File,
        marker::PhantomData,
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        os::fd::{AsFd as _, AsRawFd as _, BorrowedFd},
        path::Path,
        process::Command,
    };

    /// Socket option level for MPTCP.
    const SOL_MPTCP: libc::c_int = 284;

    /// Connection-level state (`struct mptcp_info`), available since Linux 5.16.
    const MPTCP_INFO: libc::c_int = 1;

    /// Per-subflow `struct tcp_info` entries.
    const MPTCP_TCPINFO: libc::c_int = 2;

    /// Per-subflow local and remote addresses (`struct mptcp_subflow_addrs`).
    const MPTCP_SUBFLOW_ADDRS: libc::c_int = 3;

    /// Size of `struct mptcp_subflow_data`, which prefixes per-subflow entries.
    const SUBFLOW_DATA_SIZE: usize = 16;

    /// Prefix of `struct tcp_info` through `tcpi_bytes_acked`.
    const TCP_INFO_SIZE: usize = 128;

    /// Offset of `tcpi_bytes_acked` in `struct tcp_info`.
    const TCP_INFO_BYTES_ACKED: usize = 120;

    /// Size of `struct mptcp_subflow_addrs` (two `sockaddr_storage` values).
    const SUBFLOW_ADDRS_SIZE: usize = 256;

    /// Most subflows the in-kernel path manager permits per connection.
    const MAX_SUBFLOWS: usize = 8;

    /// `tcpi_state` of an established subflow.
    const TCP_ESTABLISHED: u8 = 1;

    /// Environment variable that turns skipped MPTCP coverage into a failure.
    const REQUIRE: &str = "COMMONWARE_REQUIRE_MPTCP";

    /// Marks a test binary re-executed inside fresh user and network namespaces.
    const NAMESPACED: &str = "COMMONWARE_MPTCP_NAMESPACED";

    /// Report that the environment cannot exercise part of `test`.
    ///
    /// Panics instead when `COMMONWARE_REQUIRE_MPTCP` is set, so validation runs
    /// can require that MPTCP coverage was exercised.
    pub(crate) fn skip(test: &str, reason: &str) {
        assert!(
            std::env::var_os(REQUIRE).is_none(),
            "{test} requires MPTCP coverage: {reason}"
        );
        eprintln!("SKIPPED {test}: {reason}");
    }

    /// Returns the error from creating an MPTCP socket in the calling thread's
    /// network namespace, if any.
    pub(crate) fn creation_error() -> Option<i32> {
        create(libc::AF_INET, libc::IPPROTO_MPTCP)
            .err()
            .and_then(|err| err.raw_os_error())
    }

    /// Returns whether the calling thread's network namespace creates MPTCP
    /// sockets whose negotiation can be observed.
    pub(crate) fn supported() -> Result<(), String> {
        let fd = create(libc::AF_INET, libc::IPPROTO_MPTCP)
            .map_err(|err| format!("MPTCP sockets unavailable: {err}"))?;
        token(fd.as_fd())
            .map(|_| ())
            .ok_or_else(|| "MPTCP_INFO unsupported (requires Linux 5.16)".into())
    }

    /// Read a socket option into `buf`, returning the length written.
    fn getsockopt(
        fd: BorrowedFd<'_>,
        level: libc::c_int,
        name: libc::c_int,
        buf: &mut [u8],
    ) -> io::Result<usize> {
        let mut len = buf.len() as libc::socklen_t;

        // SAFETY: `fd` is a live descriptor, `buf` is writable for `len` bytes,
        // and the kernel writes at most `len` bytes before getsockopt returns.
        if unsafe {
            libc::getsockopt(
                fd.as_raw_fd(),
                level,
                name,
                buf.as_mut_ptr().cast(),
                &mut len,
            )
        } == -1
        {
            return Err(io::Error::last_os_error());
        }
        Ok(len as usize)
    }

    /// Returns the protocol a socket was created with.
    pub(crate) fn protocol(fd: BorrowedFd<'_>) -> libc::c_int {
        let mut buf = [0; size_of::<libc::c_int>()];
        getsockopt(fd, libc::SOL_SOCKET, libc::SO_PROTOCOL, &mut buf).expect("SO_PROTOCOL");
        libc::c_int::from_ne_bytes(buf)
    }

    /// Returns the MPTCP connection token, or `None` if the socket uses TCP
    /// (including after fallback during negotiation) or MPTCP_INFO is unavailable.
    pub(crate) fn token(fd: BorrowedFd<'_>) -> Option<u32> {
        // `mptcpi_token` follows six one-byte fields and the 32-bit `mptcpi_flags`.
        let mut info = [0; 16];
        getsockopt(fd, SOL_MPTCP, MPTCP_INFO, &mut info).ok()?;
        Some(u32::from_ne_bytes(info[12..16].try_into().unwrap()))
    }

    /// State of one subflow of an MPTCP connection.
    #[derive(Clone, Debug)]
    pub(crate) struct Subflow {
        pub(crate) local: SocketAddr,
        pub(crate) remote: SocketAddr,
        pub(crate) established: bool,
        pub(crate) bytes_acked: u64,
    }

    /// Returns the subflows of an MPTCP connection.
    pub(crate) fn subflows(fd: BorrowedFd<'_>) -> Vec<Subflow> {
        // Retry if a subflow joins or closes between the two queries.
        for _ in 0..100 {
            let infos = subflow_entries(fd, MPTCP_TCPINFO, TCP_INFO_SIZE);
            let addrs = subflow_entries(fd, MPTCP_SUBFLOW_ADDRS, SUBFLOW_ADDRS_SIZE);
            if infos.len() != addrs.len() {
                continue;
            }
            return infos
                .iter()
                .zip(&addrs)
                .map(|(info, addrs)| Subflow {
                    local: sockaddr(&addrs[..SUBFLOW_ADDRS_SIZE / 2]),
                    remote: sockaddr(&addrs[SUBFLOW_ADDRS_SIZE / 2..]),
                    established: info[0] == TCP_ESTABLISHED,
                    bytes_acked: u64::from_ne_bytes(
                        info[TCP_INFO_BYTES_ACKED..TCP_INFO_BYTES_ACKED + 8]
                            .try_into()
                            .unwrap(),
                    ),
                })
                .collect();
        }
        panic!("subflows kept changing between queries");
    }

    /// Query per-subflow entries of `size` bytes each.
    fn subflow_entries(fd: BorrowedFd<'_>, name: libc::c_int, size: usize) -> Vec<Vec<u8>> {
        // Fill `size_subflow_data` and `size_user`. The kernel requires
        // `num_subflows` and `size_kernel` to be zero and sets them on return.
        let mut buf = vec![0; SUBFLOW_DATA_SIZE + MAX_SUBFLOWS * size];
        buf[0..4].copy_from_slice(&(SUBFLOW_DATA_SIZE as u32).to_ne_bytes());
        buf[12..16].copy_from_slice(&(size as u32).to_ne_bytes());
        getsockopt(fd, SOL_MPTCP, name, &mut buf).expect("per-subflow MPTCP option");

        let count = u32::from_ne_bytes(buf[4..8].try_into().unwrap()) as usize;
        let stride = u32::from_ne_bytes(buf[12..16].try_into().unwrap()) as usize;
        assert_eq!(stride, size, "kernel entries are smaller than expected");
        buf[SUBFLOW_DATA_SIZE..]
            .chunks_exact(size)
            .take(count.min(MAX_SUBFLOWS))
            .map(<[u8]>::to_vec)
            .collect()
    }

    /// Decode an IPv4 or IPv6 `sockaddr_storage`.
    fn sockaddr(storage: &[u8]) -> SocketAddr {
        let family = libc::sa_family_t::from_ne_bytes(storage[..2].try_into().unwrap());
        let port = u16::from_be_bytes(storage[2..4].try_into().unwrap());
        match libc::c_int::from(family) {
            libc::AF_INET => {
                let ip: [u8; 4] = storage[4..8].try_into().unwrap();
                SocketAddr::new(Ipv4Addr::from(ip).into(), port)
            }
            libc::AF_INET6 => {
                let ip: [u8; 16] = storage[8..24].try_into().unwrap();
                SocketAddr::new(Ipv6Addr::from(ip).into(), port)
            }
            family => panic!("unexpected address family {family}"),
        }
    }

    /// Run `body` as root of fresh user and network namespaces that are
    /// discarded when it returns.
    ///
    /// Re-executes `test` (a full test path from [module_path]) under `unshare`,
    /// which needs unprivileged user namespaces or root. Skips when namespaces
    /// or `ip mptcp` are unavailable.
    pub(crate) fn namespaced(test: &str, body: impl FnOnce()) {
        if std::env::var_os(NAMESPACED).is_some() {
            return body();
        }

        // libtest names omit the crate.
        let name = test.split_once("::").map_or(test, |(_, name)| name);
        const UNSHARE: [&str; 3] = ["--user", "--map-root-user", "--net"];
        match Command::new("unshare")
            .args(UNSHARE)
            .args(["ip", "mptcp", "limits", "show"])
            .output()
        {
            Ok(output) if output.status.success() => {}
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return skip(
                    name,
                    &format!("cannot configure MPTCP namespaces: {}", stderr.trim()),
                );
            }
            Err(err) => return skip(name, &format!("cannot run unshare: {err}")),
        }

        let output = Command::new("unshare")
            .args(UNSHARE)
            .arg("--")
            .arg(std::env::current_exe().expect("test binary path"))
            .args([name, "--exact", "--nocapture"])
            .env(NAMESPACED, "1")
            .output()
            .expect("failed to run namespaced test");
        let stdout = String::from_utf8_lossy(&output.stdout);
        eprint!("{stdout}{}", String::from_utf8_lossy(&output.stderr));
        assert!(output.status.success(), "namespaced {name} failed");
        assert!(stdout.contains("1 passed"), "namespaced {name} did not run");
    }

    /// A network namespace held open by descriptor.
    pub(crate) struct Netns(File);

    impl Netns {
        /// Create a network namespace with loopback up, without entering it.
        pub(crate) fn new() -> Self {
            let netns = std::thread::spawn(|| {
                // SAFETY: unshare takes only flags. It moves just this thread,
                // which exits after opening its new namespace.
                let result = unsafe { libc::unshare(libc::CLONE_NEWNET) };
                assert_eq!(result, 0, "unshare: {}", io::Error::last_os_error());
                Self::current()
            })
            .join()
            .unwrap();
            netns.run("ip link set lo up");
            netns
        }

        /// Open the calling thread's network namespace.
        fn current() -> Self {
            Self(File::open("/proc/thread-self/ns/net").expect("open network namespace"))
        }

        /// Move the calling thread into this namespace until the guard drops.
        ///
        /// Sockets belong to the namespace of the thread that creates them.
        /// Threads spawned while entered start in this namespace.
        pub(crate) fn enter(&self) -> Entered {
            let previous = Self::current();
            setns(&self.0);
            Entered {
                previous,
                _thread: PhantomData,
            }
        }

        /// Run a whitespace-separated command inside this namespace.
        pub(crate) fn run(&self, command: &str) {
            let _entered = self.enter();
            let mut args = command.split_whitespace();
            let output = Command::new(args.next().expect("empty command"))
                .args(args)
                .output()
                .unwrap_or_else(|err| panic!("{command}: {err}"));
            assert!(
                output.status.success(),
                "{command}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        /// Set `net.mptcp.enabled` in this namespace.
        pub(crate) fn set_mptcp_enabled(&self, enabled: bool) {
            let _entered = self.enter();
            std::fs::write(
                "/proc/sys/net/mptcp/enabled",
                if enabled { "1" } else { "0" },
            )
            .expect("write net.mptcp.enabled");
        }

        /// Path that `ip` accepts as a network namespace.
        fn path(&self) -> String {
            format!("/proc/{}/fd/{}", std::process::id(), self.0.as_raw_fd())
        }
    }

    /// Move the calling thread into the network namespace `fd`.
    fn setns(fd: &File) {
        // SAFETY: `fd` is an open network namespace descriptor, and setns moves
        // only the calling thread.
        let result = unsafe { libc::setns(fd.as_raw_fd(), libc::CLONE_NEWNET) };
        assert_eq!(result, 0, "setns: {}", io::Error::last_os_error());
    }

    /// Restores the calling thread's previous network namespace on drop.
    pub(crate) struct Entered {
        previous: Netns,
        // Namespace membership is per thread.
        _thread: PhantomData<*const ()>,
    }

    impl Drop for Entered {
        fn drop(&mut self) {
            setns(&self.previous.0);
        }
    }

    /// Returns whether the kernel provides IPv6.
    pub(crate) fn ipv6() -> bool {
        Path::new("/proc/net/if_inet6").exists()
    }

    /// Two routed paths between client and server namespaces for one address family.
    ///
    /// Path `i` (1 or 2) links veth `c{i}` in the client to `s{i}` in the server,
    /// addressed `10.0.{i}.{1,2}/24` or `fd00:{i}::{1,2}/64`. Both ends permit
    /// one additional subflow and the server announces its path 2 address, so a
    /// connection dialed over path 1 adds a subflow over path 2.
    pub(crate) struct Paths {
        pub(crate) client: Netns,
        pub(crate) server: Netns,
        ipv6: bool,
    }

    impl Paths {
        /// Create both namespaces and paths.
        pub(crate) fn new(ipv6: bool) -> Self {
            let paths = Self {
                client: Netns::new(),
                server: Netns::new(),
                ipv6,
            };
            for path in 1..=2 {
                paths.client.run(&format!(
                    "ip link add c{path} type veth peer name s{path} netns {}",
                    paths.server.path()
                ));
                for (netns, prefix, host) in [(&paths.client, "c", 1), (&paths.server, "s", 2)] {
                    let address = paths.address(path, host);
                    let options = if ipv6 { "/64 nodad" } else { "/24" };
                    netns.run(&format!(
                        "ip addr add {address}{options} dev {prefix}{path}"
                    ));
                    netns.run(&format!("ip link set {prefix}{path} up"));
                }
            }
            for netns in [&paths.client, &paths.server] {
                netns.run("ip mptcp limits set subflows 1 add_addr_accepted 1");
            }
            paths.server.run(&format!(
                "ip mptcp endpoint add {} dev s2 id 1 signal",
                paths.address(2, 2)
            ));
            paths
        }

        /// Address of `host` (1 for the client, 2 for the server) on `path`.
        pub(crate) fn address(&self, path: u8, host: u8) -> IpAddr {
            if self.ipv6 {
                Ipv6Addr::new(0xfd00, path.into(), 0, 0, 0, 0, 0, host.into()).into()
            } else {
                Ipv4Addr::new(10, 0, path, host).into()
            }
        }

        /// Returns the subflow over `path`, if present.
        pub(crate) fn subflow(&self, subflows: &[Subflow], path: u8) -> Option<Subflow> {
            subflows
                .iter()
                .find(|subflow| {
                    subflow.local.ip() == self.address(path, 1)
                        && subflow.remote.ip() == self.address(path, 2)
                })
                .cloned()
        }

        /// Unspecified server address, accepting subflows on every path.
        pub(crate) fn unspecified(&self) -> IpAddr {
            if self.ipv6 {
                Ipv6Addr::UNSPECIFIED.into()
            } else {
                Ipv4Addr::UNSPECIFIED.into()
            }
        }

        /// Take down the client end of path 1, which also drops the server end's carrier.
        pub(crate) fn interrupt_initial(&self) {
            self.client.run("ip link set c1 down");
        }
    }

    #[test]
    fn test_socket_protocol_and_flags() {
        let mptcp = match create(libc::AF_INET, libc::IPPROTO_MPTCP) {
            Ok(_) => libc::IPPROTO_MPTCP,
            Err(err) => {
                assert!(unavailable(&err), "MPTCP socket creation failed: {err}");
                skip("test_socket_protocol_and_flags", &err.to_string());
                libc::IPPROTO_TCP
            }
        };
        let mut addresses = vec![SocketAddr::from((Ipv4Addr::LOCALHOST, 0))];
        if ipv6() {
            addresses.push(SocketAddr::from((Ipv6Addr::LOCALHOST, 0)));
        }
        for address in addresses {
            for (requested, expected) in [(false, libc::IPPROTO_TCP), (true, mptcp)] {
                let fd = socket(address, requested).unwrap();
                assert_eq!(protocol(fd.as_fd()), expected);

                // SAFETY: `fd` owns a live descriptor and F_GETFL/F_GETFD take no argument.
                let (status, descriptor) = unsafe {
                    (
                        libc::fcntl(fd.as_raw_fd(), libc::F_GETFL),
                        libc::fcntl(fd.as_raw_fd(), libc::F_GETFD),
                    )
                };
                assert_ne!(status & libc::O_NONBLOCK, 0);
                assert_ne!(descriptor & libc::FD_CLOEXEC, 0);
            }
        }
    }

    #[test]
    fn test_unavailable_classifies_capability_errors_only() {
        // Capability errors reported when MPTCP is disabled or not built in.
        for errno in [libc::ENOPROTOOPT, libc::EPROTONOSUPPORT, libc::EINVAL] {
            assert!(unavailable(&io::Error::from_raw_os_error(errno)), "{errno}");
        }

        // Unrelated failures, including policy denials (for example from SELinux
        // or eBPF), resource exhaustion, and unsupported families, must surface.
        for errno in [
            libc::EACCES,
            libc::EPERM,
            libc::EMFILE,
            libc::ENFILE,
            libc::ENOBUFS,
            libc::ENOMEM,
            libc::EAFNOSUPPORT,
            libc::EADDRINUSE,
            libc::EADDRNOTAVAIL,
        ] {
            assert!(
                !unavailable(&io::Error::from_raw_os_error(errno)),
                "{errno}"
            );
        }
        assert!(!unavailable(&io::Error::other("not an OS error")));
    }
}
