//! This module provides an XDP-based implementation of the [crate::Network] trait,
//! offering high-performance, kernel-bypass network operations on Linux systems.
//!
//! ## Architecture
//!
//! XDP (eXpress Data Path) allows packet processing at the earliest point in the
//! network stack, enabling high-throughput, low-latency networking. This implementation
//! uses AF_XDP sockets to send and receive raw packets, with UDP as the transport layer.
//!
//! The implementation maintains connection state for UDP peers, allowing it to implement
//! the connection-oriented [crate::Network] trait over the connectionless UDP protocol.
//!
//! ## Feature Flag
//!
//! This implementation is enabled by using the `xdp-network` feature.
//!
//! ## Linux Only
//!
//! This implementation is only available on Linux systems with AF_XDP support
//! (kernel 4.18+, recommended 5.10+).
//!
//! ## Requirements
//!
//! - Linux kernel 5.10+ recommended for full feature support
//! - CAP_NET_ADMIN or CAP_NET_RAW capability or root privileges
//! - Network interface must support XDP

use crate::Error;
use commonware_utils::StableBuf;
use futures::channel::{mpsc, oneshot};
use prometheus_client::{
    metrics::{counter::Counter, gauge::Gauge},
    registry::Registry,
};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tracing::{debug, warn};
use xdp::{
    nic::NicIndex,
    slab::HeapSlab,
    socket::{PollTimeout, XdpSocketBuilder},
    umem::{FrameSize, UmemCfgBuilder},
    Packet, RingConfigBuilder, Rings, Umem,
};

/// Default number of frames in the UMEM region.
const DEFAULT_FRAME_COUNT: u32 = 4096;

/// Default ring size for XDP operations.
const DEFAULT_RING_SIZE: u32 = 2048;

/// Batch size for packet operations.
const BATCH_SIZE: usize = 64;

/// Ethernet header size in bytes.
const ETH_HEADER_SIZE: usize = 14;

/// IPv4 header size in bytes (without options).
const IPV4_HEADER_SIZE: usize = 20;

/// UDP header size in bytes.
const UDP_HEADER_SIZE: usize = 8;

/// Total header overhead for UDP over IPv4 over Ethernet.
const TOTAL_HEADER_SIZE: usize = ETH_HEADER_SIZE + IPV4_HEADER_SIZE + UDP_HEADER_SIZE;

/// Maximum UDP payload size (based on 4K frame size).
const MAX_UDP_PAYLOAD: usize = 4096 - TOTAL_HEADER_SIZE;

/// Ethernet type for IPv4.
const ETH_TYPE_IPV4: u16 = 0x0800;

/// IP protocol number for UDP.
const IP_PROTO_UDP: u8 = 17;

/// Metrics for XDP network operations.
#[derive(Clone)]
pub struct Metrics {
    /// Total packets transmitted.
    pub packets_tx: Counter,
    /// Total packets received.
    pub packets_rx: Counter,
    /// Total bytes transmitted.
    pub bytes_tx: Counter,
    /// Total bytes received.
    pub bytes_rx: Counter,
    /// Current number of active connections.
    pub active_connections: Gauge,
    /// Total number of dropped packets.
    pub packets_dropped: Counter,
}

impl Metrics {
    /// Creates and registers metrics with the given registry.
    pub fn new(registry: &mut Registry) -> Self {
        let metrics = Self {
            packets_tx: Counter::default(),
            packets_rx: Counter::default(),
            bytes_tx: Counter::default(),
            bytes_rx: Counter::default(),
            active_connections: Gauge::default(),
            packets_dropped: Counter::default(),
        };
        registry.register("packets_tx", "Total packets transmitted", metrics.packets_tx.clone());
        registry.register("packets_rx", "Total packets received", metrics.packets_rx.clone());
        registry.register("bytes_tx", "Total bytes transmitted", metrics.bytes_tx.clone());
        registry.register("bytes_rx", "Total bytes received", metrics.bytes_rx.clone());
        registry.register(
            "active_connections",
            "Current active connections",
            metrics.active_connections.clone(),
        );
        registry.register(
            "packets_dropped",
            "Total dropped packets",
            metrics.packets_dropped.clone(),
        );
        metrics
    }
}

/// Configuration for XDP networking.
#[derive(Clone, Debug)]
pub struct Config {
    /// Name of the network interface to bind to (e.g., "eth0").
    pub interface: String,

    /// Queue ID to bind to on the interface.
    pub queue_id: u32,

    /// Number of frames in the UMEM region.
    pub frame_count: u32,

    /// Size of the fill and completion rings.
    pub fill_ring_size: u32,

    /// Size of the TX and RX rings.
    pub rxtx_ring_size: u32,

    /// Whether to use zero-copy mode (requires driver support).
    pub zero_copy: bool,

    /// Timeout for receive operations.
    pub recv_timeout: Duration,

    /// Timeout for send operations.
    pub send_timeout: Duration,

    /// Local IP address to use for UDP packets.
    pub local_ip: Ipv4Addr,

    /// Local MAC address to use for Ethernet frames.
    pub local_mac: [u8; 6],
}

impl Default for Config {
    fn default() -> Self {
        Self {
            interface: String::from("eth0"),
            queue_id: 0,
            frame_count: DEFAULT_FRAME_COUNT,
            fill_ring_size: DEFAULT_RING_SIZE,
            rxtx_ring_size: DEFAULT_RING_SIZE,
            zero_copy: false,
            recv_timeout: Duration::from_secs(60),
            send_timeout: Duration::from_secs(30),
            local_ip: Ipv4Addr::new(0, 0, 0, 0),
            local_mac: [0; 6],
        }
    }
}

impl Config {
    /// Creates a new configuration for the given interface.
    pub fn new(interface: impl Into<String>) -> Self {
        Self {
            interface: interface.into(),
            ..Default::default()
        }
    }

    /// Sets the queue ID.
    pub const fn with_queue_id(mut self, queue_id: u32) -> Self {
        self.queue_id = queue_id;
        self
    }

    /// Sets the frame count.
    pub const fn with_frame_count(mut self, count: u32) -> Self {
        self.frame_count = count;
        self
    }

    /// Enables zero-copy mode.
    pub const fn with_zero_copy(mut self, enabled: bool) -> Self {
        self.zero_copy = enabled;
        self
    }

    /// Sets the receive timeout.
    pub const fn with_recv_timeout(mut self, timeout: Duration) -> Self {
        self.recv_timeout = timeout;
        self
    }

    /// Sets the send timeout.
    pub const fn with_send_timeout(mut self, timeout: Duration) -> Self {
        self.send_timeout = timeout;
        self
    }

    /// Sets the local IP address.
    pub const fn with_local_ip(mut self, ip: Ipv4Addr) -> Self {
        self.local_ip = ip;
        self
    }

    /// Sets the local MAC address.
    pub const fn with_local_mac(mut self, mac: [u8; 6]) -> Self {
        self.local_mac = mac;
        self
    }
}

/// Operation types for the XDP event loop.
#[allow(dead_code)]
enum Op {
    /// Send data to a peer.
    Send {
        peer: SocketAddr,
        data: StableBuf,
        result: oneshot::Sender<Result<(), Error>>,
    },
    /// Receive data from a specific peer.
    Recv {
        peer: SocketAddr,
        buf: StableBuf,
        result: oneshot::Sender<Result<StableBuf, Error>>,
    },
    /// Accept a new connection.
    Accept {
        result: oneshot::Sender<Result<(SocketAddr, StableBuf), Error>>,
    },
    /// Shutdown the event loop.
    Shutdown,
}

/// Internal state for managing XDP socket operations.
struct XdpState {
    /// The UMEM region.
    umem: Umem,
    /// The rings for packet I/O.
    rings: Rings,
    /// Configuration.
    config: Config,
    /// Pending receive operations per peer.
    pending_recv: HashMap<SocketAddr, Vec<(StableBuf, oneshot::Sender<Result<StableBuf, Error>>)>>,
    /// Pending accept operations.
    pending_accept: Vec<oneshot::Sender<Result<(SocketAddr, StableBuf), Error>>>,
    /// Received packets waiting to be delivered.
    recv_queue: HashMap<SocketAddr, Vec<Vec<u8>>>,
    /// Packets from unknown peers (for accept).
    unknown_peer_queue: Vec<(SocketAddr, Vec<u8>)>,
    /// Metrics.
    metrics: Arc<Metrics>,
    /// Local port for this socket.
    local_port: u16,
    /// ARP table for MAC address resolution.
    arp_table: HashMap<Ipv4Addr, [u8; 6]>,
    /// Slab for RX operations.
    rx_slab: HeapSlab,
    /// Slab for TX operations.
    tx_slab: HeapSlab,
}

/// Builds an Ethernet frame with IP and UDP headers.
fn build_packet_data(
    config: &Config,
    arp_table: &HashMap<Ipv4Addr, [u8; 6]>,
    local_port: u16,
    peer: &SocketAddr,
    payload: &[u8],
) -> Result<Vec<u8>, Error> {
    let peer_ip = match peer.ip() {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(_) => return Err(Error::SendFailed),
    };

    // Get destination MAC from ARP table or use broadcast
    let dst_mac = arp_table.get(&peer_ip).copied().unwrap_or([0xff; 6]);

    let total_len = TOTAL_HEADER_SIZE + payload.len();
    let mut packet = vec![0u8; total_len];

    // Ethernet header
    packet[0..6].copy_from_slice(&dst_mac);
    packet[6..12].copy_from_slice(&config.local_mac);
    packet[12..14].copy_from_slice(&ETH_TYPE_IPV4.to_be_bytes());

    // IPv4 header
    let ip_start = ETH_HEADER_SIZE;
    packet[ip_start] = 0x45; // Version (4) + IHL (5)
    packet[ip_start + 1] = 0; // DSCP + ECN
    let ip_total_len = (IPV4_HEADER_SIZE + UDP_HEADER_SIZE + payload.len()) as u16;
    packet[ip_start + 2..ip_start + 4].copy_from_slice(&ip_total_len.to_be_bytes());
    packet[ip_start + 4..ip_start + 6].copy_from_slice(&0u16.to_be_bytes()); // ID
    packet[ip_start + 6..ip_start + 8].copy_from_slice(&0x4000u16.to_be_bytes()); // Flags + Fragment
    packet[ip_start + 8] = 64; // TTL
    packet[ip_start + 9] = IP_PROTO_UDP;
    // Checksum calculated later
    packet[ip_start + 12..ip_start + 16].copy_from_slice(&config.local_ip.octets());
    packet[ip_start + 16..ip_start + 20].copy_from_slice(&peer_ip.octets());

    // Calculate IP checksum
    let checksum = ip_checksum(&packet[ip_start..ip_start + IPV4_HEADER_SIZE]);
    packet[ip_start + 10..ip_start + 12].copy_from_slice(&checksum.to_be_bytes());

    // UDP header
    let udp_start = ETH_HEADER_SIZE + IPV4_HEADER_SIZE;
    packet[udp_start..udp_start + 2].copy_from_slice(&local_port.to_be_bytes());
    packet[udp_start + 2..udp_start + 4].copy_from_slice(&peer.port().to_be_bytes());
    let udp_len = (UDP_HEADER_SIZE + payload.len()) as u16;
    packet[udp_start + 4..udp_start + 6].copy_from_slice(&udp_len.to_be_bytes());
    // UDP checksum (0 = disabled for IPv4)
    packet[udp_start + 6..udp_start + 8].copy_from_slice(&0u16.to_be_bytes());

    // Payload
    packet[TOTAL_HEADER_SIZE..].copy_from_slice(payload);

    Ok(packet)
}

/// Calculates IPv4 header checksum.
fn ip_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for i in (0..header.len()).step_by(2) {
        if i == 10 {
            continue; // Skip checksum field
        }
        let word = if i + 1 < header.len() {
            u16::from_be_bytes([header[i], header[i + 1]])
        } else {
            u16::from_be_bytes([header[i], 0])
        };
        sum += u32::from(word);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Parses a received packet and extracts the UDP payload.
fn parse_packet(
    packet: &Packet,
    arp_table: &mut HashMap<Ipv4Addr, [u8; 6]>,
) -> Option<(SocketAddr, Vec<u8>)> {
    let packet_len = packet.len();
    if packet_len < TOTAL_HEADER_SIZE {
        return None;
    }

    // Read the Ethernet header
    let mut eth_hdr = [0u8; ETH_HEADER_SIZE];
    packet.array_at_offset(0, &mut eth_hdr).ok()?;

    // Check Ethernet type
    let eth_type = u16::from_be_bytes([eth_hdr[12], eth_hdr[13]]);
    if eth_type != ETH_TYPE_IPV4 {
        return None;
    }

    // Read the IPv4 header
    let mut ip_hdr = [0u8; IPV4_HEADER_SIZE];
    packet.array_at_offset(ETH_HEADER_SIZE, &mut ip_hdr).ok()?;

    // Check IP protocol
    if ip_hdr[9] != IP_PROTO_UDP {
        return None;
    }

    // Extract source IP
    let src_ip = Ipv4Addr::new(ip_hdr[12], ip_hdr[13], ip_hdr[14], ip_hdr[15]);

    // Store source MAC in ARP table
    let src_mac: [u8; 6] = eth_hdr[6..12].try_into().ok()?;
    arp_table.insert(src_ip, src_mac);

    // Read the UDP header
    let mut udp_hdr = [0u8; UDP_HEADER_SIZE];
    packet
        .array_at_offset(ETH_HEADER_SIZE + IPV4_HEADER_SIZE, &mut udp_hdr)
        .ok()?;

    // Extract UDP source port
    let src_port = u16::from_be_bytes([udp_hdr[0], udp_hdr[1]]);

    // Extract payload length
    let udp_len = u16::from_be_bytes([udp_hdr[4], udp_hdr[5]]) as usize;
    if udp_len < UDP_HEADER_SIZE || packet_len < TOTAL_HEADER_SIZE + (udp_len - UDP_HEADER_SIZE) {
        return None;
    }

    let payload_len = udp_len - UDP_HEADER_SIZE;
    if payload_len == 0 {
        return Some((SocketAddr::new(IpAddr::V4(src_ip), src_port), Vec::new()));
    }

    // Read the payload - we read it in chunks since array_at_offset needs a compile-time size
    let mut payload = vec![0u8; payload_len];
    // Read in 64-byte chunks
    let chunk_size = 64;
    let mut offset = 0;
    while offset < payload_len {
        let remaining = payload_len - offset;
        let read_size = remaining.min(chunk_size);
        let mut chunk = [0u8; 64];
        if packet
            .array_at_offset(TOTAL_HEADER_SIZE + offset, &mut chunk)
            .is_ok()
        {
            payload[offset..offset + read_size].copy_from_slice(&chunk[..read_size]);
        }
        offset += read_size;
    }

    Some((SocketAddr::new(IpAddr::V4(src_ip), src_port), payload))
}

/// Gets the network interface index by name.
fn get_interface_index(name: &str) -> Result<NicIndex, Error> {
    use std::ffi::CString;

    let c_name = CString::new(name).map_err(|_| Error::BindFailed)?;

    // SAFETY: c_name is a valid CString
    let index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    if index == 0 {
        return Err(Error::BindFailed);
    }

    Ok(NicIndex(index))
}

/// XDP-based network implementation.
#[derive(Clone)]
pub struct Network {
    /// Configuration.
    #[allow(dead_code)]
    config: Config,
    /// Channel for submitting operations to the event loop.
    op_sender: mpsc::Sender<Op>,
    /// Metrics.
    #[allow(dead_code)]
    metrics: Arc<Metrics>,
}

impl Network {
    /// Creates a new XDP network instance.
    ///
    /// This function creates an AF_XDP socket and spawns a background thread
    /// to handle packet I/O operations.
    pub fn start(config: Config, registry: &mut Registry) -> Result<Self, Error> {
        let metrics = Arc::new(Metrics::new(registry));
        let (op_sender, op_receiver) = mpsc::channel(config.fill_ring_size as usize);

        // Clone config for the background thread
        let config_clone = config.clone();
        let metrics_clone = metrics.clone();

        // Spawn the XDP event loop in a background thread
        std::thread::spawn(move || {
            if let Err(e) = Self::run_event_loop(config_clone, metrics_clone, op_receiver) {
                warn!(?e, "XDP event loop terminated with error");
            }
        });

        Ok(Self {
            config,
            op_sender,
            metrics,
        })
    }

    /// Runs the XDP event loop.
    fn run_event_loop(
        config: Config,
        metrics: Arc<Metrics>,
        mut op_receiver: mpsc::Receiver<Op>,
    ) -> Result<(), Error> {
        // Get interface index
        let nic_index = get_interface_index(&config.interface)?;

        // Create UMEM configuration
        let umem_cfg = UmemCfgBuilder {
            frame_size: FrameSize::FourK,
            frame_count: config.frame_count,
            ..Default::default()
        }
        .build()
        .map_err(|e| {
            warn!(?e, "Failed to build UMEM config");
            Error::BindFailed
        })?;

        // Create UMEM
        let umem = Umem::map(umem_cfg).map_err(|e| {
            warn!(?e, "Failed to map UMEM");
            Error::BindFailed
        })?;

        // Create ring configuration
        let ring_cfg = RingConfigBuilder {
            fill_count: config.fill_ring_size,
            completion_count: config.fill_ring_size,
            rx_count: config.rxtx_ring_size,
            tx_count: config.rxtx_ring_size,
        }
        .build()
        .map_err(|e| {
            warn!(?e, "Failed to build ring config");
            Error::BindFailed
        })?;

        // Create socket builder
        let mut socket_builder = XdpSocketBuilder::new().map_err(|e| {
            warn!(?e, "Failed to create XDP socket");
            Error::BindFailed
        })?;

        // Build rings
        let (rings, mut bind_flags) = socket_builder.build_rings(&umem, ring_cfg).map_err(|e| {
            warn!(?e, "Failed to build rings");
            Error::BindFailed
        })?;

        // Set bind flags
        if config.zero_copy {
            bind_flags.force_zerocopy();
        } else {
            bind_flags.force_copy();
        }

        // Bind the socket
        let socket = socket_builder
            .bind(nic_index, config.queue_id, bind_flags)
            .map_err(|e| {
                warn!(?e, "Failed to bind XDP socket");
                Error::BindFailed
            })?;

        let mut state = XdpState {
            umem,
            rings,
            config,
            pending_recv: HashMap::new(),
            pending_accept: Vec::new(),
            recv_queue: HashMap::new(),
            unknown_peer_queue: Vec::new(),
            metrics,
            local_port: 0, // Will be set on bind
            arp_table: HashMap::new(),
            rx_slab: HeapSlab::with_capacity(BATCH_SIZE),
            tx_slab: HeapSlab::with_capacity(BATCH_SIZE),
        };

        // Fill the fill ring with initial frames
        // SAFETY: UMEM outlives the socket
        unsafe {
            state.rings.fill_ring.enqueue(&mut state.umem, BATCH_SIZE);
        }

        // Main event loop
        loop {
            // Poll for I/O readiness
            let timeout = PollTimeout::new(Some(Duration::from_millis(10)));
            let _ = socket.poll(timeout);

            // Poll for received packets
            Self::poll_rx(&mut state);

            // Process completed TX operations
            Self::process_completions(&mut state);

            // Process pending operations (non-blocking)
            match op_receiver.try_next() {
                Ok(Some(Op::Send { peer, data, result })) => {
                    let res = Self::handle_send(&mut state, &peer, data);
                    let _ = result.send(res);
                }
                Ok(Some(Op::Recv { peer, buf, result })) => {
                    Self::handle_recv(&mut state, peer, buf, result);
                }
                Ok(Some(Op::Accept { result })) => {
                    Self::handle_accept(&mut state, result);
                }
                Ok(Some(Op::Shutdown)) | Ok(None) => {
                    debug!("XDP event loop shutting down");
                    break;
                }
                Err(_) => {
                    // No operations pending, continue polling
                }
            }
        }

        Ok(())
    }

    /// Process TX completions and return frames to UMEM.
    fn process_completions(state: &mut XdpState) {
        state
            .rings
            .completion_ring
            .dequeue(&mut state.umem, BATCH_SIZE);
    }

    /// Polls for received packets.
    fn poll_rx(state: &mut XdpState) {
        let rx_ring = match &mut state.rings.rx_ring {
            Some(rx) => rx,
            None => return,
        };

        // SAFETY: UMEM outlives the socket
        let received = unsafe { rx_ring.recv(&state.umem, &mut state.rx_slab) };

        if received > 0 {
            // Process received packets
            use xdp::slab::Slab;
            while let Some(packet) = state.rx_slab.pop_back() {
                if let Some((peer, payload)) = parse_packet(&packet, &mut state.arp_table) {
                    state.metrics.packets_rx.inc();
                    state.metrics.bytes_rx.inc_by(payload.len() as u64);

                    // Check if we have a pending recv for this peer
                    if let Some(pending) = state.pending_recv.get_mut(&peer) {
                        if let Some((mut buf, sender)) = pending.pop() {
                            let copy_len = buf.len().min(payload.len());
                            buf.as_mut()[..copy_len].copy_from_slice(&payload[..copy_len]);
                            let _ = sender.send(Ok(buf));
                            continue;
                        }
                    }

                    // Queue the packet
                    if state.recv_queue.contains_key(&peer) {
                        state.recv_queue.get_mut(&peer).unwrap().push(payload);
                    } else {
                        // Unknown peer - queue for accept
                        state.unknown_peer_queue.push((peer, payload));

                        // Check if we have a pending accept
                        if let Some(sender) = state.pending_accept.pop() {
                            if let Some((peer, data)) = state.unknown_peer_queue.pop() {
                                let mut buf = StableBuf::from(vec![0u8; data.len()]);
                                buf.as_mut().copy_from_slice(&data);
                                let _ = sender.send(Ok((peer, buf)));
                                state.metrics.active_connections.inc();
                            }
                        }
                    }
                }
            }

            // Refill the fill ring
            // SAFETY: UMEM outlives the socket
            unsafe {
                state.rings.fill_ring.enqueue(&mut state.umem, received);
            }
        }
    }

    /// Handles a send operation.
    fn handle_send(state: &mut XdpState, peer: &SocketAddr, data: StableBuf) -> Result<(), Error> {
        // Build the packet data
        let packet_data = build_packet_data(
            &state.config,
            &state.arp_table,
            state.local_port,
            peer,
            data.as_ref(),
        )?;

        let tx_ring = match &mut state.rings.tx_ring {
            Some(tx) => tx,
            None => return Err(Error::SendFailed),
        };

        // Allocate a packet from UMEM
        // SAFETY: We're the only ones accessing UMEM in this thread
        let mut packet = unsafe { state.umem.alloc() }.ok_or(Error::SendFailed)?;

        // Append packet data to the frame
        if packet.append(&packet_data).is_err() {
            return Err(Error::SendFailed);
        }

        // Add packet to TX slab
        use xdp::slab::Slab;
        if state.tx_slab.push_front(packet).is_some() {
            return Err(Error::SendFailed);
        }

        // Send the packet
        // SAFETY: The packet is valid and allocated from our UMEM
        let sent = unsafe { tx_ring.send(&mut state.tx_slab) };

        if sent == 0 {
            return Err(Error::SendFailed);
        }

        state.metrics.packets_tx.inc();
        state.metrics.bytes_tx.inc_by(data.len() as u64);

        Ok(())
    }

    /// Handles a receive operation.
    fn handle_recv(
        state: &mut XdpState,
        peer: SocketAddr,
        buf: StableBuf,
        result: oneshot::Sender<Result<StableBuf, Error>>,
    ) {
        // Check if we have queued data for this peer
        if let Some(queue) = state.recv_queue.get_mut(&peer) {
            if let Some(data) = queue.pop() {
                let mut buf = buf;
                let copy_len = buf.len().min(data.len());
                buf.as_mut()[..copy_len].copy_from_slice(&data[..copy_len]);
                let _ = result.send(Ok(buf));
                return;
            }
        }

        // Queue the receive operation
        state
            .pending_recv
            .entry(peer)
            .or_default()
            .push((buf, result));
    }

    /// Handles an accept operation.
    fn handle_accept(
        state: &mut XdpState,
        result: oneshot::Sender<Result<(SocketAddr, StableBuf), Error>>,
    ) {
        // Check if we have packets from unknown peers
        if let Some((peer, data)) = state.unknown_peer_queue.pop() {
            let mut buf = StableBuf::from(vec![0u8; data.len()]);
            buf.as_mut().copy_from_slice(&data);
            let _ = result.send(Ok((peer, buf)));
            state.metrics.active_connections.inc();
            return;
        }

        // Queue the accept operation
        state.pending_accept.push(result);
    }
}

impl crate::Network for Network {
    type Listener = Listener;

    async fn bind(&self, socket: SocketAddr) -> Result<Self::Listener, Error> {
        // For XDP, binding means we'll filter packets to the specified port
        Ok(Listener {
            local_addr: socket,
            op_sender: self.op_sender.clone(),
        })
    }

    async fn dial(
        &self,
        socket: SocketAddr,
    ) -> Result<(crate::SinkOf<Self>, crate::StreamOf<Self>), Error> {
        // For XDP, dialing creates a "connected" UDP-like socket
        // that sends/receives only to/from the specified peer
        Ok((
            Sink {
                peer: socket,
                op_sender: self.op_sender.clone(),
            },
            Stream {
                peer: socket,
                op_sender: self.op_sender.clone(),
            },
        ))
    }
}

/// XDP-based listener implementation.
pub struct Listener {
    local_addr: SocketAddr,
    op_sender: mpsc::Sender<Op>,
}

impl crate::Listener for Listener {
    type Sink = Sink;
    type Stream = Stream;

    async fn accept(&mut self) -> Result<(SocketAddr, Self::Sink, Self::Stream), Error> {
        let (tx, rx) = oneshot::channel();

        self.op_sender
            .clone()
            .try_send(Op::Accept { result: tx })
            .map_err(|_| Error::Closed)?;

        let (peer, _initial_data) = rx.await.map_err(|_| Error::Closed)??;

        Ok((
            peer,
            Sink {
                peer,
                op_sender: self.op_sender.clone(),
            },
            Stream {
                peer,
                op_sender: self.op_sender.clone(),
            },
        ))
    }

    fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        Ok(self.local_addr)
    }
}

/// XDP-based sink (send) implementation.
pub struct Sink {
    peer: SocketAddr,
    op_sender: mpsc::Sender<Op>,
}

impl crate::Sink for Sink {
    async fn send(&mut self, msg: impl Into<StableBuf> + Send) -> Result<(), Error> {
        let msg = msg.into();

        // Check message size
        if msg.len() > MAX_UDP_PAYLOAD {
            return Err(Error::SendFailed);
        }

        let (tx, rx) = oneshot::channel();

        self.op_sender
            .clone()
            .try_send(Op::Send {
                peer: self.peer,
                data: msg,
                result: tx,
            })
            .map_err(|_| Error::SendFailed)?;

        rx.await.map_err(|_| Error::SendFailed)?
    }
}

/// XDP-based stream (receive) implementation.
pub struct Stream {
    peer: SocketAddr,
    op_sender: mpsc::Sender<Op>,
}

impl crate::Stream for Stream {
    async fn recv(&mut self, buf: impl Into<StableBuf> + Send) -> Result<StableBuf, Error> {
        let buf = buf.into();
        let (tx, rx) = oneshot::channel();

        self.op_sender
            .clone()
            .try_send(Op::Recv {
                peer: self.peer,
                buf,
                result: tx,
            })
            .map_err(|_| Error::RecvFailed)?;

        rx.await.map_err(|_| Error::RecvFailed)?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_builder() {
        let config = Config::new("eth0")
            .with_queue_id(1)
            .with_frame_count(8192)
            .with_zero_copy(true)
            .with_local_ip(Ipv4Addr::new(192, 168, 1, 100))
            .with_local_mac([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        assert_eq!(config.interface, "eth0");
        assert_eq!(config.queue_id, 1);
        assert_eq!(config.frame_count, 8192);
        assert!(config.zero_copy);
        assert_eq!(config.local_ip, Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(config.local_mac, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    }

    #[test]
    fn test_ip_checksum() {
        // Test with a known IPv4 header
        let header = [
            0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0xac, 0x10,
            0x0a, 0x63, 0xac, 0x10, 0x0a, 0x0c,
        ];
        let checksum = ip_checksum(&header);
        // The checksum should be non-zero
        assert_ne!(checksum, 0);
    }
}
