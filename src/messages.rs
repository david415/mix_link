// sessions.rs - client and server protocol sessions
// Copyright (C) 2018  David Anthony Stainton.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

extern crate snow;
extern crate ecdh_wrapper;

use std::time::SystemTime;
use std::u64;

use subtle::ConstantTimeEq;
use byteorder::{ByteOrder, BigEndian};
use snow::Builder;
use ecdh_wrapper::{PrivateKey, PublicKey};

use super::errors::{HandshakeError, RekeyError};
use super::errors::{ClientHandshakeError, ServerHandshakeError, ReceiveMessageError, SendMessageError};

use super::constants::{NOISE_MESSAGE_MAX_SIZE,
                       NOISE_MESSAGE_HEADER_SIZE,
                       NOISE_HANDSHAKE_MESSAGE1_SIZE,
                       NOISE_HANDSHAKE_MESSAGE2_SIZE,
                       NOISE_HANDSHAKE_MESSAGE3_SIZE,
                       NOISE_PARAMS,
                       PROLOGUE,
                       PROLOGUE_SIZE,
                       MAC_SIZE,
                       MAX_ADDITIONAL_DATA_SIZE,
                       AUTH_MESSAGE_SIZE};


struct AuthenticateMessage {
    additional_data: Vec<u8>,
    unix_time: u32,
}

impl AuthenticateMessage {
    fn to_vec(&self) -> Result<Vec<u8>, &'static str> {
        if self.additional_data.len() > MAX_ADDITIONAL_DATA_SIZE {
            return Err("additional data exceeds maximum allowed size");
        }
        let zero_bytes = [0u8; MAX_ADDITIONAL_DATA_SIZE];
        let mut out = Vec::new();
        out.push(self.additional_data.len() as u8);
        out.extend_from_slice(&self.additional_data);
        out.extend_from_slice(&zero_bytes[..zero_bytes.len()-self.additional_data.len()]);
        let mut _time = [0u8; 4];
        BigEndian::write_u32(&mut _time, self.unix_time);
        out.extend_from_slice(&_time);
        Ok(out)
    }
}

fn authenticate_message_from_bytes(b: &[u8]) -> Result<AuthenticateMessage, &'static str> {
    if b.len() != AUTH_MESSAGE_SIZE {
        return Err("authenticate message is not the valid size");
    }
    let ad_len = b[0] as usize;
    Ok(AuthenticateMessage {
        additional_data: b[1..1+ad_len].to_vec(),
        unix_time: BigEndian::read_u32(&b[1+MAX_ADDITIONAL_DATA_SIZE..]),
    })
}

pub struct PeerCredentials {
    pub additional_data: Vec<u8>,
    pub public_key: PublicKey,
}

pub trait PeerAuthenticator {
    fn is_peer_valid(&self, peer_credentials: &PeerCredentials) -> bool;
}

#[derive(PartialEq, Debug, Clone)]
pub enum State {
    Init,
    SentClientHandshake1,
    ReceivedServerHandshake1,
    ReceivedClientHandshake1,
    SentServerHandshake1,
    DataTransfer,
    Disconnected,
    Invalid,
}

pub struct SessionConfig {
    pub authenticator: Box<PeerAuthenticator+Send>,
    pub authentication_key: PrivateKey,
    pub peer_public_key: Option<PublicKey>,
    pub additional_data: Vec<u8>,
}

pub struct MessageFactory {
    session: snow::Session,
    state: State,
    additional_data: Vec<u8>,
    authenticator: Box<PeerAuthenticator+Send>,
    is_initiator: bool,
}

impl MessageFactory {
    pub fn new(config: SessionConfig, is_initiator: bool) -> Result<MessageFactory, HandshakeError> {
        let noise_params;
        match NOISE_PARAMS.parse() {
            Ok(x) => {
                noise_params = x;
            },
            Err(_) => return Err(HandshakeError::InvalidNoiseSpecError),
        }
        let noise_builder: Builder = Builder::new(noise_params);
        if is_initiator {
            if !config.peer_public_key.is_some() {
                return Err(HandshakeError::NoPeerKeyError);
            }
            let session = match noise_builder
                .local_private_key(&config.authentication_key.to_vec())
                .remote_public_key(&(config.peer_public_key.unwrap()).to_vec())
                .prologue(&PROLOGUE)
                .build_initiator() {
                    Ok(x) => x,
                    Err(_) => return Err(HandshakeError::SessionCreateError),
                };
            return Ok(MessageFactory {
                state: State::Init,
                additional_data: config.additional_data,
                authenticator: config.authenticator,
                session,
                is_initiator,
            });
        }
        let session = match noise_builder
            .local_private_key(&config.authentication_key.to_vec())
            .prologue(&PROLOGUE)
            .build_responder() {
                Ok(x) => x,
                Err(_) => return Err(HandshakeError::SessionCreateError),
            };
        Ok(MessageFactory {
            state: State::Init,
            additional_data: config.additional_data,
            authenticator: config.authenticator,
            session,
            is_initiator,
        })
    }

    pub fn rekey_key(&mut self) -> Result<Vec<u8>, RekeyError> {
        let mut new_key = vec![0u8; 32];
        let payload = vec![0u8; 0];
        let nonce = u64::MAX;
        let _ = self.session.write_message_with_nonce(nonce, &payload, &mut new_key)?;
        Ok(new_key)
    }

    pub fn rekey(&mut self) -> Result<(), RekeyError> {
        let new_key = self.rekey_key()?;
        if self.is_initiator {
            self.session.rekey(Some(&new_key), None)?;
        } else {
            self.session.rekey(None, Some(&new_key))?;
        }
        Ok(())
    }

    pub fn client_handshake1(&mut self) -> Result<[u8; NOISE_HANDSHAKE_MESSAGE1_SIZE], ClientHandshakeError> {
	// -> (prologue), e, f
        let mut msg = [0u8; NOISE_MESSAGE_MAX_SIZE];
        let _len = match self.session.write_message(&[0u8;0], &mut msg) {
            Ok(x) => x,
            Err(_) => return Err(ClientHandshakeError::Noise1WriteError),
        };
        let mut msg1 = [0u8; NOISE_HANDSHAKE_MESSAGE1_SIZE];
        msg1[0] = PROLOGUE[0];
        msg1[PROLOGUE_SIZE..].copy_from_slice(&msg[.._len]);
        Ok(msg1)
    }

    pub fn sent_client_handshake1(&mut self) {
        self.state = State::SentClientHandshake1;
    }

    pub fn sent_client_handshake2(&mut self) {
        self.state = State::DataTransfer;
    }

    pub fn client_handshake2(&mut self) -> Result<[u8; NOISE_HANDSHAKE_MESSAGE3_SIZE], ClientHandshakeError> {
        let now = SystemTime::now();
        let mut msg = [0u8; NOISE_MESSAGE_MAX_SIZE];
        let our_auth = AuthenticateMessage {
            additional_data: self.additional_data.clone(),
            unix_time: now.elapsed().unwrap().as_secs() as u32,
        };
        let raw_auth = our_auth.to_vec().unwrap();
        let _len = match self.session.write_message(&raw_auth, &mut msg) {
            Ok(x) => x,
            Err(_) => return Err(ClientHandshakeError::Noise3WriteError),
        };
        assert_eq!(NOISE_HANDSHAKE_MESSAGE3_SIZE, _len);
        let mut _msg3 = [0u8; NOISE_HANDSHAKE_MESSAGE3_SIZE];
        _msg3.copy_from_slice(&msg[..NOISE_HANDSHAKE_MESSAGE3_SIZE]);
        Ok(_msg3)
    }

    pub fn received_server_handshake1(&mut self, message: [u8; NOISE_HANDSHAKE_MESSAGE2_SIZE]) -> Result<(), ClientHandshakeError> {
        let mut _raw_auth = [0u8; AUTH_MESSAGE_SIZE];
        let _len = match self.session.read_message(&message, &mut _raw_auth) {
            Ok(x) => x,
            Err(_) => return Err(ClientHandshakeError::Noise2ReadError),
        };
        let auth_msg = match authenticate_message_from_bytes(&_raw_auth) {
            Ok(x) => x,
            Err(_) => return Err(ClientHandshakeError::AuthenticationError),
        };
        let raw_peer_key = match self.session.get_remote_static() {
            Some(x) => x,
            None => return Err(ClientHandshakeError::FailedToGetRemoteStatic),
        };
        let mut peer_key = PublicKey::default();
        match peer_key.from_bytes(raw_peer_key) {
            Ok(_x) => {},
            Err(_y) => return Err(ClientHandshakeError::FailedToDecodeRemoteStatic),
        }
        let peer_credentials = PeerCredentials {
            additional_data: auth_msg.additional_data,
            public_key: peer_key,
        };
        if !self.authenticator.is_peer_valid(&peer_credentials) {
            return Err(ClientHandshakeError::AuthenticationError);
        }
        self.state = State::ReceivedServerHandshake1;
        Ok(())
    }

    pub fn received_client_handshake1(&mut self, message: [u8; NOISE_HANDSHAKE_MESSAGE1_SIZE]) -> Result<[u8; NOISE_HANDSHAKE_MESSAGE2_SIZE], ServerHandshakeError> {
        if self.state != State::Init {
            return Err(ServerHandshakeError::InvalidStateError);
        }
        if message[0..PROLOGUE_SIZE].ct_eq(&PROLOGUE).unwrap_u8() == 0 {
            return Err(ServerHandshakeError::PrologueMismatchError);
        }
        let mut _msg = [0u8; NOISE_HANDSHAKE_MESSAGE1_SIZE];
        let _len = match self.session.read_message(&message[PROLOGUE_SIZE..], &mut _msg) {
            Ok(x) => x,
            Err(_) => return Err(ServerHandshakeError::Noise1ReadError),
        };
        self.state = State::ReceivedClientHandshake1;

        // send server's handshake1 message
        let now = SystemTime::now();
        let our_auth = AuthenticateMessage {
            additional_data: self.additional_data.clone(),
            unix_time: now.elapsed().unwrap().as_secs() as u32,
        };
        let raw_auth = our_auth.to_vec().unwrap();
        let mut mesg = [0u8; NOISE_HANDSHAKE_MESSAGE2_SIZE];
        let mut _len = match self.session.write_message(&raw_auth, &mut mesg) {
            Ok(x) => x,
            Err(_) => return Err(ServerHandshakeError::Noise2WriteError),
        };
        assert_eq!(NOISE_HANDSHAKE_MESSAGE2_SIZE, _len);
        Ok(mesg)
    }

    pub fn sent_server_handshake1(&mut self) {
        self.state = State::SentServerHandshake1;
    }

    pub fn received_client_handshake2(&mut self, message: [u8; NOISE_HANDSHAKE_MESSAGE3_SIZE]) -> Result<(), ServerHandshakeError> {
        if self.state != State::SentServerHandshake1 {
            return Err(ServerHandshakeError::InvalidStateError);
        }
        let mut raw_auth = [0u8; AUTH_MESSAGE_SIZE];
        let _match = self.session.read_message(&message, &mut raw_auth);
        match _match {
            Ok(x) => x,
            Err(_) => return Err(ServerHandshakeError::Noise3ReadError),
        };
        let peer_auth = authenticate_message_from_bytes(&raw_auth).unwrap();
        let raw_peer_key = self.session.get_remote_static().unwrap();
        let mut peer_key = PublicKey::default();
        match peer_key.from_bytes(raw_peer_key) {
            Ok(_) => {},
            Err(_) => return Err(ServerHandshakeError::FailedToDecodeRemoteStatic),
        }
        let peer_credentials = PeerCredentials {
            additional_data: peer_auth.additional_data,
            public_key: peer_key,
        };
        if !self.authenticator.is_peer_valid(&peer_credentials) {
            return Err(ServerHandshakeError::AuthenticationError);
        }
        self.state = State::DataTransfer;
        Ok(())
    }

    pub fn into_transport_mode(self) -> Result<Self, HandshakeError> {
        // Transition into transport mode after handshake is finished.
        Ok(Self {
            session: self.session.into_transport_mode()?,
            state: self.state,
            additional_data: self.additional_data,
            authenticator: self.authenticator,
            is_initiator: self.is_initiator,
        })
    }

    pub fn encrypt_message(&mut self, message: Vec<u8>) -> Result<Vec<u8>, SendMessageError> {
        let ct_len = MAC_SIZE + message.len();
        if ct_len > NOISE_MESSAGE_MAX_SIZE {
            return Err(SendMessageError::InvalidMessageSize);
        }
        let mut ct_hdr = [0u8; 4];
        BigEndian::write_u32(&mut ct_hdr, ct_len as u32);
        let mut ciphertext_header = [0u8; NOISE_MESSAGE_MAX_SIZE];
        let _result = self.session.write_message(&ct_hdr, &mut ciphertext_header);
        let _header_len;
        match _result {
            Ok(x) => {
                _header_len = x;
            },
            Err(_) => {
                return Err(SendMessageError::EncryptFail)
            },
        }
        let mut ciphertext = [0u8; NOISE_MESSAGE_MAX_SIZE];
        let _result = self.session.write_message(&message, &mut ciphertext);
        let mut _payload_len;
        match _result {
            Ok(x) => {
                _payload_len = x;
            },
            Err(_) => {
                return Err(SendMessageError::EncryptFail)
            },
        }
        let mut output = Vec::new();
        output.extend_from_slice(&ciphertext_header[.._header_len]);
        output.extend_from_slice(&ciphertext[.._payload_len]);
        Ok(output)
    }

    pub fn decrypt_message_header(&mut self, message: Vec<u8>) -> Result<u32, ReceiveMessageError> {
        let mut header = [0u8; NOISE_MESSAGE_MAX_SIZE];
        match self.session.read_message(&message[..NOISE_MESSAGE_HEADER_SIZE], &mut header) {
            Ok(x) => {
                assert_eq!(x, 4);
                Ok(BigEndian::read_u32(&header[..NOISE_MESSAGE_HEADER_SIZE]))
            },
            Err(_) => Err(ReceiveMessageError::DecryptFail),
        }
    }

    pub fn decrypt_message(&mut self, message: Vec<u8>) -> Result<Vec<u8>, ReceiveMessageError> {
        let mut plaintext = [0u8; NOISE_MESSAGE_MAX_SIZE];
        match self.session.read_message(&message, &mut plaintext) {
            Ok(_len) => Ok(plaintext[.._len].to_vec()),
            Err(_) => Err(ReceiveMessageError::DecryptFail),
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate rand;
    extern crate ecdh_wrapper;
    //extern crate rustc_serialize;

    //use self::rustc_serialize::hex::ToHex;
    use self::rand::os::OsRng;
    use ecdh_wrapper::PrivateKey;
    use super::super::sphinxcrypto::constants::USER_FORWARD_PAYLOAD_SIZE;
    use super::{PeerAuthenticator, PeerCredentials};
    use super::super::commands::Command;
    use super::*;

    struct NaiveAuthenticator {}
    impl PeerAuthenticator for NaiveAuthenticator {
        fn is_peer_valid(&self, _peer_credentials: &PeerCredentials) -> bool {
            return true;
        }
    }

    #[test]
    fn message_handshake_test() {
        let mut r = OsRng::new().expect("failure to create an OS RNG");

        // server
        let server_authenticator = NaiveAuthenticator{};
        let server_keypair = PrivateKey::generate(&mut r).unwrap();
        let server_config = SessionConfig {
            authenticator: Box::new(server_authenticator),
            authentication_key: server_keypair,
            peer_public_key: None,
            additional_data: vec![],
        };
        let mut server_session = MessageFactory::new(server_config, false).unwrap();

        // client
        let client_authenticator = NaiveAuthenticator{};
        let client_keypair = PrivateKey::generate(&mut r).unwrap();
        let client_config = SessionConfig {
            authenticator: Box::new(client_authenticator),
            authentication_key: client_keypair,
            peer_public_key: Some(server_keypair.public_key()),
            additional_data: vec![],
        };
        let mut client_session = MessageFactory::new(client_config, true).unwrap();

        // handshake
        // c -> s
        let client_handshake1 = client_session.client_handshake1().unwrap();
        let _ok = client_session.sent_client_handshake1();
        let server_handshake1 = server_session.received_client_handshake1(client_handshake1).unwrap();

        // s -> c
        server_session.sent_server_handshake1();
        client_session.received_server_handshake1(server_handshake1).unwrap();

        // c -> s
        let client_handshake2 = client_session.client_handshake2().unwrap();
        client_session.sent_client_handshake2();
        server_session.received_client_handshake2(client_handshake2).unwrap();

        // data transfer phase
        server_session = server_session.into_transport_mode().unwrap();
        client_session = client_session.into_transport_mode().unwrap();

        // s -> c
        let server_cmd = Command::MessageMessage {
            queue_size_hint: 0u8,
            sequence: 0u32,
            payload: vec![0u8; USER_FORWARD_PAYLOAD_SIZE],
        };
        let server_message = server_cmd.clone().to_vec();
        let to_send = server_session.encrypt_message(server_message.clone()).unwrap();

        let _mesg_len = client_session.decrypt_message_header(to_send.clone()).unwrap();
        let raw_cmd = client_session.decrypt_message(to_send[NOISE_MESSAGE_HEADER_SIZE..].to_vec()).unwrap();
        assert_eq!(server_message, raw_cmd);

        let client_cmd = Command::NoOp{};
        let client_message = client_cmd.clone().to_vec();
        let client_to_send = client_session.encrypt_message(client_message.clone()).unwrap();
        let _mesg_len = server_session.decrypt_message_header(client_to_send.clone()).unwrap();
        let raw_cmd = server_session.decrypt_message(client_to_send[NOISE_MESSAGE_HEADER_SIZE..].to_vec()).unwrap();
        assert_eq!(raw_cmd, client_message);
    }
}