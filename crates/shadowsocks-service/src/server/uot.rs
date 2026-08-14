//! Shadowsocks UoT (UDP-over-TCP) server
//!
//! Implements the server side of sing's UoT protocol (`github.com/sagernet/sing/common/uot`).
//! Clients (mihomo, Shadowrocket, sing-box) request a magic domain as the shadowsocks TCP target
//! and then tunnel UDP datagrams inside that TCP stream, which lets UDP pass through TCP-only
//! transports like `v2ray-plugin`'s websocket mode.
//!
//! Frame layouts, on the already decrypted shadowsocks stream:
//!
//! ```text
//! v1 (sp.udp-over-tcp.arpa), v2 non-connect:  | ATYP u8 | address | port u16be | length u16be | data |
//! v2 (sp.v2.udp-over-tcp.arpa) connect:       | length u16be | data |
//! ```
//!
//! v2 additionally starts with a request header `| isConnect u8 | SOCKS5 address |`.
//!
//! NOTE: the ATYP values in the frames above are *not* the SOCKS5 ones (sing calls this codec
//! `AddrParser`): `0x00` IPv4, `0x01` IPv6, `0x02` domain. Only the v2 request header carries a
//! real SOCKS5 address. The frame codec is ported from `cfal/shoes` `src/uot/uot_common.rs`
//! (MIT licensed), see `reference/shoes-uot/PROVENANCE.md`.

use std::{
    io::{self, ErrorKind},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use log::{error, trace};
use shadowsocks::{
    lookup_then,
    net::{AddrFamily, UdpSocket as OutboundUdpSocket, get_ip_stack_capabilities},
    relay::{socks5::Address, udprelay::MAXIMUM_UDP_PAYLOAD_SIZE},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    sync::mpsc,
};

use crate::net::utils::to_ipv4_mapped;

use super::context::ServiceContext;

/// Magic domain of UoT v1 (sing's `LegacyMagicAddress`)
const UOT_V1_MAGIC_ADDRESS: &str = "sp.udp-over-tcp.arpa";
/// Magic domain of UoT v2 (sing's `MagicAddress`)
const UOT_V2_MAGIC_ADDRESS: &str = "sp.v2.udp-over-tcp.arpa";

/// Frame ATYPs (sing's `AddrParser`), which differ from the SOCKS5 ones
const UOT_ATYP_IPV4: u8 = 0x00;
const UOT_ATYP_IPV6: u8 = 0x01;
const UOT_ATYP_DOMAIN: u8 = 0x02;

/// Buffer for coalescing the small header reads of consecutive frames
const UOT_STREAM_BUFFER_SIZE: usize = 8192;

/// Datagrams in flight from client to remote. Bounded, so a slow outbound applies back-pressure
/// on the TCP stream instead of growing memory.
const UOT_SEND_CHANNEL_SIZE: usize = 64;

/// UoT protocol version, selected by the magic domain the client requested
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UotVersion {
    V1,
    V2,
}

/// Check if `addr` is a UoT magic domain, which means the stream carries UDP datagrams
/// instead of a TCP tunnel.
///
/// Clients use port 0 by convention, but the version is signalled by the domain alone.
pub fn detect_magic(addr: &Address) -> Option<UotVersion> {
    match *addr {
        Address::DomainNameAddress(ref dname, _) => match dname.as_str() {
            UOT_V1_MAGIC_ADDRESS => Some(UotVersion::V1),
            UOT_V2_MAGIC_ADDRESS => Some(UotVersion::V2),
            _ => None,
        },
        Address::SocketAddress(..) => None,
    }
}

/// How the destination of each datagram is carried
enum Mode {
    /// v1 and v2 non-connect: every frame carries its own destination
    PerPacket,
    /// v2 connect: fixed destination from the request header, frames carry payloads only
    Connected(Address),
}

/// Relay UDP datagrams tunneled in an (already decrypted) shadowsocks TCP stream.
///
/// Unlike [`super::udprelay`] there is no NAT association map: the stream itself is the
/// association, and it ends when either direction fails or the client closes.
pub async fn serve<S>(
    context: Arc<ServiceContext>,
    peer_addr: SocketAddr,
    stream: S,
    version: UotVersion,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::with_capacity(UOT_STREAM_BUFFER_SIZE, reader);

    let mode = match version {
        UotVersion::V1 => Mode::PerPacket,
        UotVersion::V2 => read_v2_request(&mut reader).await?,
    };

    match mode {
        Mode::PerPacket => trace!("established uot tunnel {} <-> ... with {:?}", peer_addr, version),
        Mode::Connected(ref target_addr) => trace!(
            "established uot tunnel {} <-> {} with {:?} connect",
            peer_addr, target_addr, version
        ),
    }

    let (sender, mut receiver) = mpsc::channel(UOT_SEND_CHANNEL_SIZE);

    // The outbound sockets are created lazily, and both directions need them, so they are owned by
    // the downlink alone and the uplink hands over datagrams through the channel.
    tokio::select! {
        result = relay_uplink(&mut reader, &mode, &sender, peer_addr) => result,
        result = relay_downlink(&context, peer_addr, &mut writer, &mut receiver, &mode) => result,
    }
}

/// Read the v2 request header `| isConnect u8 | SOCKS5 address |`
async fn read_v2_request<R>(reader: &mut R) -> io::Result<Mode>
where
    R: AsyncRead + Unpin,
{
    let is_connect = reader.read_u8().await?;
    // Unlike the frames, the request header carries a SOCKS5 address.
    let target_addr = Address::read_from(reader).await?;

    Ok(if is_connect == 0 {
        // Non-connect: multi destination, the header's address is unused.
        Mode::PerPacket
    } else {
        Mode::Connected(target_addr)
    })
}

/// client -> remote. Parses frames and forwards them to the downlink, which owns the sockets.
async fn relay_uplink<R>(
    reader: &mut R,
    mode: &Mode,
    sender: &mpsc::Sender<(Address, Vec<u8>)>,
    peer_addr: SocketAddr,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
{
    loop {
        match read_frame(reader, mode).await? {
            Some(packet) => {
                if sender.send(packet).await.is_err() {
                    // Downlink exited, it will report the error.
                    return Ok(());
                }
            }
            None => {
                trace!("uot tunnel {} closed by client", peer_addr);
                return Ok(());
            }
        }
    }
}

/// remote -> client. Owns the outbound sockets, so it also sends the uplink's datagrams.
async fn relay_downlink<W>(
    context: &ServiceContext,
    peer_addr: SocketAddr,
    writer: &mut W,
    receiver: &mut mpsc::Receiver<(Address, Vec<u8>)>,
    mode: &Mode,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut outbound_ipv4_socket: Option<OutboundUdpSocket> = None;
    let mut outbound_ipv6_socket: Option<OutboundUdpSocket> = None;
    let mut outbound_ipv4_buffer = Vec::new();
    let mut outbound_ipv6_buffer = Vec::new();
    let mut frame = Vec::new();

    loop {
        tokio::select! {
            packet_received_opt = receiver.recv() => {
                let (target_addr, data) = match packet_received_opt {
                    Some(p) => p,
                    None => {
                        // Uplink is done, no more datagrams will be sent.
                        return Ok(());
                    }
                };

                if context.check_outbound_blocked(&target_addr).await {
                    error!("uot client {} outbound {} blocked by ACL rules", peer_addr, target_addr);
                    continue;
                }

                trace!("uot relay {} -> {} with {} bytes", peer_addr, target_addr, data.len());

                if let Err(err) = send_outbound_packet(
                    context,
                    &mut outbound_ipv4_socket,
                    &mut outbound_ipv6_socket,
                    &target_addr,
                    &data,
                )
                .await
                {
                    // One unreachable destination must not tear down the whole tunnel.
                    error!(
                        "uot relay {} -> {} with {} bytes, error: {}",
                        peer_addr, target_addr, data.len(), err
                    );
                }
            }

            received_opt = receive_from_outbound_opt(&outbound_ipv4_socket, &mut outbound_ipv4_buffer), if outbound_ipv4_socket.is_some() => {
                match received_opt {
                    Ok((n, addr)) => {
                        write_respond_packet(writer, &mut frame, mode, peer_addr, addr, &outbound_ipv4_buffer[..n]).await?;
                    }
                    Err(err) => {
                        error!("uot relay {} <- ... failed, error: {}", peer_addr, err);
                        // Socket failure. Reset for recreation.
                        outbound_ipv4_socket = None;
                    }
                }
            }

            received_opt = receive_from_outbound_opt(&outbound_ipv6_socket, &mut outbound_ipv6_buffer), if outbound_ipv6_socket.is_some() => {
                match received_opt {
                    Ok((n, addr)) => {
                        write_respond_packet(writer, &mut frame, mode, peer_addr, addr, &outbound_ipv6_buffer[..n]).await?;
                    }
                    Err(err) => {
                        error!("uot relay {} <- ... failed, error: {}", peer_addr, err);
                        // Socket failure. Reset for recreation.
                        outbound_ipv6_socket = None;
                    }
                }
            }
        }
    }
}

#[inline]
async fn receive_from_outbound_opt(
    socket: &Option<OutboundUdpSocket>,
    buf: &mut Vec<u8>,
) -> io::Result<(usize, SocketAddr)> {
    match *socket {
        None => futures::future::pending().await,
        Some(ref s) => {
            if buf.is_empty() {
                buf.resize(MAXIMUM_UDP_PAYLOAD_SIZE, 0);
            }
            s.recv_from(buf).await
        }
    }
}

/// Read one datagram from the UoT stream.
///
/// Returns `None` if the client closed the stream at a frame boundary. A partial frame is an
/// error: one `read` is not one datagram, so frames are delimited by the length prefix only.
async fn read_frame<R>(reader: &mut R, mode: &Mode) -> io::Result<Option<(Address, Vec<u8>)>>
where
    R: AsyncRead + Unpin,
{
    // The first byte doubles as the EOF probe.
    let first_byte = match reader.read_u8().await {
        Ok(b) => b,
        Err(ref err) if err.kind() == ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err),
    };

    let (target_addr, payload_len) = match *mode {
        Mode::PerPacket => {
            let target_addr = read_frame_address(reader, first_byte).await?;
            (target_addr, reader.read_u16().await?)
        }
        Mode::Connected(ref target_addr) => (
            target_addr.clone(),
            u16::from_be_bytes([first_byte, reader.read_u8().await?]),
        ),
    };

    // payload_len is a u16, so this allocation is bounded by 65535 bytes.
    let mut payload = vec![0u8; payload_len as usize];
    reader.read_exact(&mut payload).await?;

    Ok(Some((target_addr, payload)))
}

/// Read a frame address, `atyp` already consumed by the caller's EOF probe
async fn read_frame_address<R>(reader: &mut R, atyp: u8) -> io::Result<Address>
where
    R: AsyncRead + Unpin,
{
    match atyp {
        UOT_ATYP_IPV4 => {
            let mut buf = [0u8; 4 + 2];
            reader.read_exact(&mut buf).await?;

            let ip = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
            let port = u16::from_be_bytes([buf[4], buf[5]]);
            Ok(Address::SocketAddress(SocketAddr::new(ip.into(), port)))
        }
        UOT_ATYP_IPV6 => {
            let mut buf = [0u8; 16 + 2];
            reader.read_exact(&mut buf).await?;

            let ip = Ipv6Addr::from(<[u8; 16]>::try_from(&buf[..16]).unwrap());
            let port = u16::from_be_bytes([buf[16], buf[17]]);
            Ok(Address::SocketAddress(SocketAddr::new(ip.into(), port)))
        }
        UOT_ATYP_DOMAIN => {
            let domain_len = reader.read_u8().await? as usize;

            let mut buf = vec![0u8; domain_len + 2];
            reader.read_exact(&mut buf).await?;

            let port = u16::from_be_bytes([buf[domain_len], buf[domain_len + 1]]);
            let dname = std::str::from_utf8(&buf[..domain_len])
                .map_err(|err| io::Error::other(format!("invalid uot domain: {err}")))?;
            Ok(Address::DomainNameAddress(dname.to_owned(), port))
        }
        _ => Err(io::Error::other(format!("unknown uot ATYP: {atyp}"))),
    }
}

/// Write a frame address (sing's `AddrParser`, never a domain in this direction)
fn write_frame_address(buf: &mut Vec<u8>, addr: &SocketAddr) {
    match *addr {
        SocketAddr::V4(ref v4) => {
            buf.push(UOT_ATYP_IPV4);
            buf.extend_from_slice(&v4.ip().octets());
        }
        SocketAddr::V6(ref v6) => {
            buf.push(UOT_ATYP_IPV6);
            buf.extend_from_slice(&v6.ip().octets());
        }
    }
    buf.extend_from_slice(&addr.port().to_be_bytes());
}

/// Frame a datagram received from the remote and write it back to the client
async fn write_respond_packet<W>(
    writer: &mut W,
    frame: &mut Vec<u8>,
    mode: &Mode,
    peer_addr: SocketAddr,
    mut source_addr: SocketAddr,
    data: &[u8],
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    trace!(
        "uot relay {} <- {} received {} bytes",
        peer_addr,
        source_addr,
        data.len()
    );

    if data.len() > u16::MAX as usize {
        // Unreachable in practice, an UDP payload is at most 65507 bytes.
        error!(
            "uot relay {} <- {} dropped {} bytes, too large to frame",
            peer_addr,
            source_addr,
            data.len()
        );
        return Ok(());
    }

    // Convert IPv4-mapped-IPv6 back to IPv4, see `udprelay`'s respond path.
    if let SocketAddr::V6(ref v6) = source_addr
        && let Some(v4) = to_ipv4_mapped(v6.ip())
    {
        source_addr = SocketAddr::new(v4.into(), v6.port());
    }

    frame.clear();
    if let Mode::PerPacket = *mode {
        write_frame_address(frame, &source_addr);
    }
    frame.extend_from_slice(&(data.len() as u16).to_be_bytes());
    frame.extend_from_slice(data);

    writer.write_all(frame).await?;
    writer.flush().await
}

async fn send_outbound_packet(
    context: &ServiceContext,
    outbound_ipv4_socket: &mut Option<OutboundUdpSocket>,
    outbound_ipv6_socket: &mut Option<OutboundUdpSocket>,
    target_addr: &Address,
    data: &[u8],
) -> io::Result<()> {
    match *target_addr {
        Address::SocketAddress(sa) => {
            send_outbound_packet_to(context, outbound_ipv4_socket, outbound_ipv6_socket, sa, data).await
        }
        Address::DomainNameAddress(ref dname, port) => lookup_then!(context.context_ref(), dname, port, |sa| {
            send_outbound_packet_to(context, outbound_ipv4_socket, outbound_ipv6_socket, sa, data).await
        })
        .map(|_| ()),
    }
}

async fn send_outbound_packet_to(
    context: &ServiceContext,
    outbound_ipv4_socket: &mut Option<OutboundUdpSocket>,
    outbound_ipv6_socket: &mut Option<OutboundUdpSocket>,
    original_target_addr: SocketAddr,
    data: &[u8],
) -> io::Result<()> {
    let ip_stack_caps = get_ip_stack_capabilities();

    let target_addr = match original_target_addr {
        SocketAddr::V4(ref v4) => {
            // If IPv4-mapped-IPv6 is supported, all sockets are created in IPv6.
            if ip_stack_caps.support_ipv4_mapped_ipv6 {
                SocketAddr::new(v4.ip().to_ipv6_mapped().into(), v4.port())
            } else {
                original_target_addr
            }
        }
        SocketAddr::V6(ref v6) => {
            // If IPv6 is not supported. Try to map it back to IPv4.
            if !ip_stack_caps.support_ipv6 || !ip_stack_caps.support_ipv4_mapped_ipv6 {
                match v6.ip().to_ipv4_mapped() {
                    Some(v4) => SocketAddr::new(v4.into(), v6.port()),
                    None => original_target_addr,
                }
            } else {
                original_target_addr
            }
        }
    };

    let socket = match target_addr {
        SocketAddr::V4(..) => match *outbound_ipv4_socket {
            Some(ref mut socket) => socket,
            None => {
                let socket =
                    OutboundUdpSocket::connect_any_with_opts(AddrFamily::Ipv4, context.connect_opts_ref()).await?;
                outbound_ipv4_socket.insert(socket)
            }
        },
        SocketAddr::V6(..) => match *outbound_ipv6_socket {
            Some(ref mut socket) => socket,
            None => {
                let socket =
                    OutboundUdpSocket::connect_any_with_opts(AddrFamily::Ipv6, context.connect_opts_ref()).await?;
                outbound_ipv6_socket.insert(socket)
            }
        },
    };

    let n = socket.send_to(data, target_addr).await?;
    if n != data.len() {
        error!(
            "uot relay -> {} sent {} bytes != expected {} bytes",
            target_addr,
            n,
            data.len()
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::{net::UdpSocket, time};

    use super::*;

    const TEST_PEER_ADDR: &str = "127.0.0.1:12345";

    fn peer_addr() -> SocketAddr {
        TEST_PEER_ADDR.parse().unwrap()
    }

    /// `| ATYP | address | port | length | data |`
    fn encode_frame(source_addr: &SocketAddr, payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::new();
        write_frame_address(&mut frame, source_addr);
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    async fn read_one(data: &[u8], mode: &Mode) -> io::Result<Option<(Address, Vec<u8>)>> {
        let mut reader = data;
        read_frame(&mut reader, mode).await
    }

    #[test]
    fn detect_magic_matches_both_versions() {
        assert_eq!(
            detect_magic(&Address::DomainNameAddress("sp.udp-over-tcp.arpa".to_owned(), 0)),
            Some(UotVersion::V1)
        );
        assert_eq!(
            detect_magic(&Address::DomainNameAddress("sp.v2.udp-over-tcp.arpa".to_owned(), 0)),
            Some(UotVersion::V2)
        );
        // The port is not part of the signal
        assert_eq!(
            detect_magic(&Address::DomainNameAddress("sp.udp-over-tcp.arpa".to_owned(), 53)),
            Some(UotVersion::V1)
        );
        assert_eq!(
            detect_magic(&Address::DomainNameAddress("www.example.com".to_owned(), 0)),
            None
        );
        assert_eq!(detect_magic(&Address::SocketAddress(peer_addr())), None);
    }

    #[tokio::test]
    async fn read_frame_address_parses_all_atyps() {
        let ipv4 = [UOT_ATYP_IPV4, 192, 168, 1, 1, 0x1F, 0x90];
        let (addr, payload) = read_one(&encode_frame_bytes(&ipv4, b"v4"), &Mode::PerPacket)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(addr, Address::SocketAddress("192.168.1.1:8080".parse().unwrap()));
        assert_eq!(payload, b"v4");

        let mut ipv6 = vec![UOT_ATYP_IPV6];
        ipv6.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        ipv6.extend_from_slice(&443u16.to_be_bytes());
        let (addr, payload) = read_one(&encode_frame_bytes(&ipv6, b"v6"), &Mode::PerPacket)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(addr, Address::SocketAddress("[::1]:443".parse().unwrap()));
        assert_eq!(payload, b"v6");

        let mut domain = vec![UOT_ATYP_DOMAIN, 11];
        domain.extend_from_slice(b"example.com");
        domain.extend_from_slice(&53u16.to_be_bytes());
        let (addr, payload) = read_one(&encode_frame_bytes(&domain, b"dns"), &Mode::PerPacket)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(addr, Address::DomainNameAddress("example.com".to_owned(), 53));
        assert_eq!(payload, b"dns");
    }

    fn encode_frame_bytes(addr: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut frame = addr.to_vec();
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    /// The frame ATYPs are not the SOCKS5 ones: `0x01` is IPv6 here, IPv4 in SOCKS5.
    #[tokio::test]
    async fn read_frame_address_rejects_socks5_atyps() {
        for atyp in [0x03u8, 0x04u8] {
            let err = read_one(&[atyp, 1, 2, 3, 4, 5, 6, 7, 8], &Mode::PerPacket)
                .await
                .unwrap_err();
            assert!(err.to_string().contains("unknown uot ATYP"), "{err}");
        }

        // ATYP 0x01 is IPv4 in SOCKS5, IPv6 here
        let mut socks5_ipv4 = vec![0x01u8, 1, 2, 3, 4];
        socks5_ipv4.extend_from_slice(&[0u8; 12]);
        socks5_ipv4.extend_from_slice(&53u16.to_be_bytes());

        let (addr, _) = read_one(&encode_frame_bytes(&socks5_ipv4, b""), &Mode::PerPacket)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(addr, Address::SocketAddress("[102:304::]:53".parse().unwrap()));
    }

    #[test]
    fn write_frame_address_is_byte_exact() {
        let mut buf = Vec::new();
        write_frame_address(&mut buf, &"192.168.1.1:8080".parse().unwrap());
        assert_eq!(buf, vec![UOT_ATYP_IPV4, 192, 168, 1, 1, 0x1F, 0x90]);

        let mut expected = vec![UOT_ATYP_IPV6];
        expected.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        expected.extend_from_slice(&443u16.to_be_bytes());

        let mut buf = Vec::new();
        write_frame_address(&mut buf, &"[::1]:443".parse().unwrap());
        assert_eq!(buf, expected);
    }

    #[tokio::test]
    async fn read_frame_handles_coalesced_frames() {
        let first = "192.168.1.1:8080".parse().unwrap();
        let second = "[::1]:443".parse().unwrap();

        // One read is not one datagram: two frames concatenated, plus an empty payload one.
        let mut stream = encode_frame(&first, b"one");
        stream.extend_from_slice(&encode_frame(&second, b"two"));
        stream.extend_from_slice(&encode_frame(&first, b""));

        let mut reader: &[u8] = &stream;
        for expected in [
            (Address::SocketAddress(first), b"one".to_vec()),
            (Address::SocketAddress(second), b"two".to_vec()),
            (Address::SocketAddress(first), Vec::new()),
        ] {
            assert_eq!(
                read_frame(&mut reader, &Mode::PerPacket).await.unwrap().unwrap(),
                expected
            );
        }

        // Closed at a frame boundary
        assert!(read_frame(&mut reader, &Mode::PerPacket).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn read_frame_handles_maximum_payload() {
        let addr = "192.168.1.1:8080".parse().unwrap();
        let payload = vec![0xABu8; u16::MAX as usize];

        let (_, read_payload) = read_one(&encode_frame(&addr, &payload), &Mode::PerPacket)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(read_payload, payload);
    }

    #[tokio::test]
    async fn read_frame_rejects_partial_frame() {
        let addr = "192.168.1.1:8080".parse().unwrap();
        let frame = encode_frame(&addr, b"truncated");

        for cut in 1..frame.len() {
            let err = read_one(&frame[..cut], &Mode::PerPacket).await.unwrap_err();
            assert_eq!(err.kind(), ErrorKind::UnexpectedEof, "cut at {cut}");
        }
    }

    #[tokio::test]
    async fn read_frame_reassembles_fragments() {
        let addr: SocketAddr = "192.168.1.1:8080".parse().unwrap();
        let frame = encode_frame(&addr, b"fragmented payload");

        let (client, server) = tokio::io::duplex(64);
        let mut server = BufReader::with_capacity(UOT_STREAM_BUFFER_SIZE, server);

        tokio::spawn(async move {
            let mut client = client;
            for chunk in frame.chunks(3) {
                client.write_all(chunk).await.unwrap();
                client.flush().await.unwrap();
                time::sleep(Duration::from_millis(1)).await;
            }
        });

        let (read_addr, payload) = read_frame(&mut server, &Mode::PerPacket).await.unwrap().unwrap();
        assert_eq!(read_addr, Address::SocketAddress(addr));
        assert_eq!(payload, b"fragmented payload");
    }

    #[tokio::test]
    async fn read_frame_connected_mode_has_no_address() {
        let target_addr = Address::DomainNameAddress("example.com".to_owned(), 53);
        let mode = Mode::Connected(target_addr.clone());

        let mut stream = Vec::new();
        stream.extend_from_slice(&3u16.to_be_bytes());
        stream.extend_from_slice(b"one");
        stream.extend_from_slice(&0u16.to_be_bytes());

        let mut reader: &[u8] = &stream;
        assert_eq!(
            read_frame(&mut reader, &mode).await.unwrap().unwrap(),
            (target_addr.clone(), b"one".to_vec())
        );
        assert_eq!(
            read_frame(&mut reader, &mode).await.unwrap().unwrap(),
            (target_addr, Vec::new())
        );
        assert!(read_frame(&mut reader, &mode).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn read_v2_request_selects_mode() {
        let target_addr = Address::DomainNameAddress("example.com".to_owned(), 53);

        for (is_connect, connected) in [(1u8, true), (0u8, false)] {
            let mut request = vec![is_connect];
            target_addr.write_to_buf(&mut request);

            let mut reader: &[u8] = &request;
            match read_v2_request(&mut reader).await.unwrap() {
                Mode::Connected(addr) => {
                    assert!(connected);
                    assert_eq!(addr, target_addr);
                }
                Mode::PerPacket => assert!(!connected),
            }
        }
    }

    /// Echoes datagrams back to their sender until dropped
    async fn spawn_udp_echo() -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let local_addr = socket.local_addr().unwrap();

        tokio::spawn(async move {
            let mut buf = vec![0u8; 1500];
            loop {
                let (n, src) = socket.recv_from(&mut buf).await.unwrap();
                socket.send_to(&buf[..n], src).await.unwrap();
            }
        });

        local_addr
    }

    #[tokio::test]
    async fn serve_v1_relays_datagrams() {
        let echo_addr = spawn_udp_echo().await;

        let (mut client, server) = tokio::io::duplex(MAXIMUM_UDP_PAYLOAD_SIZE);
        tokio::spawn(serve(
            Arc::new(ServiceContext::new()),
            peer_addr(),
            server,
            UotVersion::V1,
        ));

        client.write_all(&encode_frame(&echo_addr, b"ping")).await.unwrap();

        let (source_addr, payload) = time::timeout(Duration::from_secs(5), read_frame(&mut client, &Mode::PerPacket))
            .await
            .expect("timed out waiting for the echoed datagram")
            .unwrap()
            .unwrap();

        assert_eq!(source_addr, Address::SocketAddress(echo_addr));
        assert_eq!(payload, b"ping");
    }

    #[tokio::test]
    async fn serve_v2_connect_relays_datagrams() {
        let echo_addr = spawn_udp_echo().await;

        let (mut client, server) = tokio::io::duplex(MAXIMUM_UDP_PAYLOAD_SIZE);
        tokio::spawn(serve(
            Arc::new(ServiceContext::new()),
            peer_addr(),
            server,
            UotVersion::V2,
        ));

        // Request header, then address-less frames
        let mut request = vec![1u8];
        Address::SocketAddress(echo_addr).write_to_buf(&mut request);
        request.extend_from_slice(&4u16.to_be_bytes());
        request.extend_from_slice(b"ping");
        client.write_all(&request).await.unwrap();

        let mode = Mode::Connected(Address::SocketAddress(echo_addr));
        let (_, payload) = time::timeout(Duration::from_secs(5), read_frame(&mut client, &mode))
            .await
            .expect("timed out waiting for the echoed datagram")
            .unwrap()
            .unwrap();

        assert_eq!(payload, b"ping");
    }

    #[tokio::test]
    async fn serve_v2_non_connect_relays_datagrams() {
        let echo_addr = spawn_udp_echo().await;

        let (mut client, server) = tokio::io::duplex(MAXIMUM_UDP_PAYLOAD_SIZE);
        tokio::spawn(serve(
            Arc::new(ServiceContext::new()),
            peer_addr(),
            server,
            UotVersion::V2,
        ));

        // isConnect = 0, so the header's address is ignored and frames carry their own.
        let mut request = vec![0u8];
        Address::DomainNameAddress("example.com".to_owned(), 53).write_to_buf(&mut request);
        request.extend_from_slice(&encode_frame(&echo_addr, b"ping"));
        client.write_all(&request).await.unwrap();

        let (source_addr, payload) = time::timeout(Duration::from_secs(5), read_frame(&mut client, &Mode::PerPacket))
            .await
            .expect("timed out waiting for the echoed datagram")
            .unwrap()
            .unwrap();

        assert_eq!(source_addr, Address::SocketAddress(echo_addr));
        assert_eq!(payload, b"ping");
    }
}
