use chacha20::{cipher::NewStreamCipher, ChaCha20, Nonce};
use p256::{EncodedPoint, NistP256, PublicKey, ecdh::EphemeralSecret, elliptic_curve::{ecdh::SharedSecret, generic_array::typenum::Unsigned, sec1::UncompressedPointSize}};
use rand_core::{OsRng, RngCore};
use sha3::Digest;

use crate::errors::*;
use std::net::*;

const SOCKET_BIND_ADDRESS: &str = "127.0.0.1";
const PRIMARY_SOCKET_PORT: u16 = 4741;
const SECONDARY_SOCKET_PORT: u16 = 4742;

const CONNECTION_REQUEST_RESPONSE_OK: u8 = 0;
const CONNECTION_REQUEST_RESPONSE_BUSY: u8 = 1;

const NONCE_SIZE: usize = <<ChaCha20 as NewStreamCipher>::NonceSize as Unsigned>::USIZE;

pub struct VoiceChatClient {
    primary_socket: UdpSocket,
    secondary_socket: UdpSocket,
    is_connection_initiator: bool,
}

impl VoiceChatClient {
    fn new_io_result() -> std::io::Result<VoiceChatClient> {
        Ok(VoiceChatClient {
            primary_socket: UdpSocket::bind(format!(
                "{}:{}",
                SOCKET_BIND_ADDRESS, PRIMARY_SOCKET_PORT
            ))?,
            secondary_socket: UdpSocket::bind(format!(
                "{}:{}",
                SOCKET_BIND_ADDRESS, SECONDARY_SOCKET_PORT
            ))?,
            is_connection_initiator: false,
        })
    }
    pub fn new() -> Result<VoiceChatClient> {
        VoiceChatClient::new_io_result().into_voice_chat_result(ErrorKind::FailedToCreateSockets)
    }
    pub fn call(&mut self, target_ip: IpAddr) -> Result<()> {
        let mut buf = [0u8; 1];
        let target_address = SocketAddr::new(target_ip, PRIMARY_SOCKET_PORT);
        self.primary_socket
            .connect(&target_address)
            .into_voice_chat_result(ErrorKind::FailedToConnectToTarget)?;
        self.primary_socket
            .send(&buf)
            .into_voice_chat_result(ErrorKind::FailedToSendConnectionRequest)?;
        // keep receiving on the socket until you receive a response from the requested endpoint
        loop {
            let recv_amount = self
                .primary_socket
                .recv(&mut buf)
                .into_voice_chat_result(ErrorKind::FailedToReceiveConnectionRequestResponse)?;
            match buf[0] {
                CONNECTION_REQUEST_RESPONSE_BUSY => {
                    return Err(ErrorKind::UserIsBusy.into_empty_error())
                }
                CONNECTION_REQUEST_RESPONSE_OK => {
                    self.is_connection_initiator = true;
                    self.perform_handshake()?
                }
                _ => return Err(ErrorKind::InvalidConnectionRequestResponse.into_empty_error()),
            }
        }
    }
    fn perform_handshake(&self) -> Result<()> {
        let my_secret = EphemeralSecret::random(&mut rand_core::OsRng);
        let my_pk_bytes = EncodedPoint::from(my_secret.public_key());
        self.primary_socket
            .send(my_pk_bytes.as_ref())
            .into_voice_chat_result(ErrorKind::FailedToSendPublicKey)?;
        let mut other_pk_bytes = [0u8; <UncompressedPointSize<NistP256> as Unsigned>::USIZE];
        let recv_amount = self
            .primary_socket
            .recv(&mut other_pk_bytes)
            .into_voice_chat_result(ErrorKind::FailedToReceivePublicKey)?;
        if recv_amount != other_pk_bytes.len() {
            return Err(ErrorKind::FailedToReceivePublicKey.into_empty_error());
        }
        let shared_secret = my_secret.diffie_hellman(
            &PublicKey::from_sec1_bytes(&other_pk_bytes)
                .into_empty_voice_chat_result(ErrorKind::FailedToPerformDiffieHellman)?,
        );
        if self.is_connection_initiator {
            let mut send_stream_nonce_bytes = [0u8; NONCE_SIZE];
            OsRng.fill_bytes(&mut send_stream_nonce_bytes);
            self.primary_socket
                .send(&send_stream_nonce_bytes)
                .into_empty_voice_chat_result(ErrorKind::FailedToSendNonce)?;
            let mut recv_stream_nonce_bytes = [0u8; NONCE_SIZE];
            OsRng.fill_bytes(&mut recv_stream_nonce_bytes);
            self.primary_socket
                .send(&recv_stream_nonce_bytes)
                .into_empty_voice_chat_result(ErrorKind::FailedToSendNonce)?;
            let send_cipher = ChaCha20::new(
                shared_secret.as_bytes(),
                Nonce::from_slice(&send_stream_nonce_bytes),
            );
            let recv_cipher = ChaCha20::new(
                shared_secret.as_bytes(),
                Nonce::from_slice(&recv_stream_nonce_bytes),
            );
        } else {
            let mut recv_stream_nonce_bytes = [0u8; NONCE_SIZE];
            self.primary_socket
                .recv(&mut recv_stream_nonce_bytes)
                .into_empty_voice_chat_result(ErrorKind::FailedToReceiveNonce)?;
            let mut send_stream_nonce_bytes = [0u8; NONCE_SIZE];
            self.primary_socket
                .recv(&mut send_stream_nonce_bytes)
                .into_empty_voice_chat_result(ErrorKind::FailedToReceiveNonce)?;
        }
        // ()
        Ok(())
    }
    fn start_call_stream(&self,key:&SharedSecret<NistP256>, send_stream_nonce_bytes: &[u8], recv_stream_nonce_bytes: &[u8])->Result<()>{
        let send_stream_cipher = ChaCha20::new(key.as_bytes(), Nonce::from_slice(send_stream_nonce_bytes));
        let recv_stream_cipher = ChaCha20::new(key.as_bytes(), Nonce::from_slice(recv_stream_nonce_bytes));
    }
}
