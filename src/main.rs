#![cfg_attr(feature = "fail-on-warnings", deny(warnings))]

use rl2tp::common::VecWriter;
use std::env;
use std::io;
use tokio::net::UdpSocket;

use rl2tp::{
    avp::{types, AVP},
    *,
};

async fn send_sccrq(
    host_name: &str,
    socket: &UdpSocket,
    requested_tunnel_id: u16,
) -> io::Result<()> {
    let sccrq = Message::Control(rl2tp::ControlMessage {
        length: 0,
        tunnel_id: 0,
        session_id: 0,
        ns: 0,
        nr: 0,
        avps: vec![
            AVP::MessageType(types::MessageType::StartControlConnectionRequest),
            AVP::ProtocolVersion(types::ProtocolVersion {
                version: 1,
                revision: 0,
            }),
            AVP::HostName(types::HostName {
                value: host_name.as_bytes().to_owned(),
            }),
            AVP::FramingCapabilities(types::FramingCapabilities::new(true, true)),
            AVP::AssignedTunnelId(types::AssignedTunnelId::from(requested_tunnel_id)),
        ],
    });

    let mut w = common::VecWriter::new();
    unsafe { sccrq.write(&mut w) };

    let sent_bytes = socket.send(&w.data).await?;
    if sent_bytes < w.len() {
        Err(io::Error::from(io::ErrorKind::Interrupted))
    } else {
        Ok(())
    }
}

async fn receive_sscrp(socket: &UdpSocket, requested_tunnel_id: u16) -> io::Result<(u16, Vec<u8>)> {
    let mut rx_buf = [0u8; 1024];
    let len = socket.recv(&mut rx_buf).await?;

    let mut r = rl2tp::common::SliceReader::from(&rx_buf[..len]);
    let sccrp =
        Message::try_read(&mut r).unwrap_or_else(|s| panic!("Invalid response received: {}", s));

    let mut maybe_assigned_tunnel_id = None;
    let mut maybe_challenge = None;
    match sccrp {
        Message::Data(_) => panic!("Received data before the control channel could be established"),
        Message::Control(mut ctrl) => {
            if ctrl.tunnel_id != requested_tunnel_id {
                panic!("Incongruent tunnel ID used by remote");
            }
            let first_avp = ctrl.avps.pop().unwrap();
            match first_avp {
                AVP::MessageType(msg_type) => {
                    if msg_type != types::MessageType::StartControlConnectionReply {
                        panic!("First AVP has an unexpected MessageType");
                    }
                }
                _ => panic!("First AVP is not a MessageType"),
            }
            for avp in ctrl.avps.into_iter() {
                match avp {
                    AVP::AssignedTunnelId(id) => maybe_assigned_tunnel_id = Some(id.value),
                    AVP::Challenge(c) => maybe_challenge = Some(c.value),
                    _ => println!("Unhandled AVP: {:?}", avp),
                }
            }
        }
    };

    let tunnel_id = maybe_assigned_tunnel_id.expect("No tunnel ID assigned by remote");
    let challenge = maybe_challenge.expect("No challenge received from remote");

    Ok((tunnel_id, challenge))
}

async fn send_scccn(
    socket: &UdpSocket,
    secret: &[u8],
    challenge: &[u8],
    tunnel_id: u16,
) -> io::Result<()> {
    let mut rsp_input = Vec::new();
    rsp_input.extend_from_slice(&tunnel_id.to_be_bytes());
    rsp_input.extend_from_slice(secret);
    rsp_input.extend_from_slice(challenge);

    let response_data = md5::compute(&rsp_input);

    let scccn = Message::Control(rl2tp::ControlMessage {
        length: 0,
        tunnel_id,
        session_id: 0,
        ns: 0,
        nr: 0,
        avps: vec![
            AVP::MessageType(types::MessageType::StartControlConnectionConnected),
            AVP::ChallengeResponse(types::ChallengeResponse {
                data: *response_data,
            }),
        ],
    });

    let mut w = VecWriter::new();
    unsafe { scccn.write(&mut w) };

    let sent_bytes = socket.send(&w.data).await?;
    if sent_bytes < w.len() {
        Err(io::Error::from(io::ErrorKind::Interrupted))
    } else {
        Ok(())
    }
}

#[tokio::main]
async fn main() -> io::Result<()> {
    const HOST_NAME: &str = "RUGGEDv0";
    const LISTEN_ADDRESS: &str = "0.0.0.0:60000";

    // Parse args
    let mut args: Vec<String> = env::args().collect();
    let remote = args.pop().expect("Remote endpoint not specified");
    let secret: String = args.pop().expect("No shared secret specified");

    let socket = UdpSocket::bind(LISTEN_ADDRESS).await?;
    socket.connect(remote).await?;

    const REQUESTED_TUNNEL_ID: u16 = 6;
    send_sccrq(HOST_NAME, &socket, REQUESTED_TUNNEL_ID).await?;

    let (tunnel_id, challenge) = receive_sscrp(&socket, REQUESTED_TUNNEL_ID).await?;

    send_scccn(&socket, secret.as_bytes(), &challenge, tunnel_id).await?;

    Ok(())
}
