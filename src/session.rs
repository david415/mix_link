// session.rs - noise based wire protocol session
// Copyright (C) 2018  David Anthony Stainton.
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

extern crate snow;
extern crate ecdh_wrapper;

use std::io::{Write, Read};
use std::time::SystemTime;
use subtle::ConstantTimeEq;
use byteorder::{ByteOrder, BigEndian};
use snow::params::NoiseParams;
use snow::NoiseBuilder;
use ecdh_wrapper::{PrivateKey, PublicKey};

use super::error::SessionError;
use super::commands::Command;

const NOISE_PARAMS: &'static str = "Noise_XX_25519_ChaChaPoly_BLAKE2b";
const PROLOGUE: [u8;1] = [0u8;1];
const NOISE_MESSAGE_MAX_SIZE: usize = 65535;

const NOISE_HANDSHAKE_MESSAGE1_SIZE: usize = 32;
const NOISE_HANDSHAKE_MESSAGE2_SIZE: usize = 96;
const NOISE_HANDSHAKE_MESSAGE3_SIZE: usize = 64;

const MAX_ADDITIONAL_DATA_SIZE: usize = 255;
const AUTH_MESSAGE_SIZE: usize = 1 + 4 + MAX_ADDITIONAL_DATA_SIZE;

struct AuthenticateMessage {
    additional_data: Vec<u8>,
    unix_time: u32,
}

impl AuthenticateMessage {
    fn to_vec(&self) -> Result<Vec<u8>, &'static str> {
        if self.additional_data.len() > MAX_ADDITIONAL_DATA_SIZE {
            return Err("additional data exceeds maximum allowed size");
        }
        let mut out = Vec::new();
        out.push(self.additional_data.len() as u8);
        out.extend_from_slice(&self.additional_data);
        let mut _time = [0u8; 4];
        BigEndian::write_u32(&mut _time, self.unix_time);
        out.extend_from_slice(&_time);
        return Ok(out);
    }
}

fn authenticate_message_from_bytes(b: &[u8]) -> Result<AuthenticateMessage, &'static str> {
    if b.len() != AUTH_MESSAGE_SIZE {
        return Err("authenticate message is not the valid size");
    }
    return Ok(AuthenticateMessage {
        additional_data: b[1..1+b.len()].to_vec(),
        unix_time: BigEndian::read_u32(&b[1+MAX_ADDITIONAL_DATA_SIZE..]),
    });
}

#[derive(PartialEq, Eq)]
enum SessionState {
    Init,
    Established,
    Invalid,
}

pub struct PeerCredentials {
    pub additional_data: Vec<u8>,
    pub public_key: PublicKey,
}

pub trait PeerAuthenticator {
    fn is_peer_valid(&self, peer_credentials: &PeerCredentials) -> bool;
}

pub struct SessionConfig {
    pub authenticator: Box<PeerAuthenticator>,
    pub authentication_key: PrivateKey,
    pub peer_public_key: Option<PublicKey>,
    pub additional_data: Vec<u8>,
}

pub struct Session {
    initiator: bool,
    session: snow::Session,
    additional_data: Vec<u8>,
    authenticator: Box<PeerAuthenticator>,
    authentication_key: PrivateKey,
    state: SessionState,
    conn_write: Option<Box<Write>>,
    conn_read: Option<Box<Read>>,
}

impl Session {
    pub fn new(session_config: SessionConfig, is_initiator: bool) -> Result<Session, SessionError> {
        let _noise_params: NoiseParams = NOISE_PARAMS.parse().unwrap();
        let _server_builder: NoiseBuilder = NoiseBuilder::new(_noise_params);
        let _session: snow::Session;
        if is_initiator {
            if !session_config.peer_public_key.is_some() {
                return Err(SessionError::NoPeerKeyError);
            }
            let _match = _server_builder
                .local_private_key(&session_config.authentication_key.to_vec())
                .remote_public_key(&(session_config.peer_public_key.unwrap()).to_vec())
                .prologue(&PROLOGUE)
                .build_initiator();
            _session = match _match {
                Ok(x) => x,
                Err(_) => return Err(SessionError::SessionCreateError),
            };
        } else {
            let _match = _server_builder
                .local_private_key(&session_config.authentication_key.to_vec())
                .prologue(&PROLOGUE)
                .build_responder();
            _session = match _match {
                Ok(x) => x,
                Err(_) => return Err(SessionError::SessionCreateError),
            };
        }
        {
            let _s = Session {
                initiator: is_initiator,
                additional_data: session_config.additional_data,
                authenticator: session_config.authenticator,
                authentication_key: session_config.authentication_key,
                session: _session,
                conn_read: None,
                conn_write: None,
                state: SessionState::Init,
            };
            Ok(_s)
        }
    }

    pub fn initialize(&mut self, conn_read: Box<Read>, conn_write: Box<Write>) -> Result<(), SessionError> {
        if self.state != SessionState::Init {
            return Err(SessionError::InvalidStateError);
        }
        self.conn_read = Some(conn_read);
        self.conn_write = Some(conn_write);
        self.handshake()?;
        self.finalize_handshake()?;
        return Ok(());
    }

    fn handshake(&mut self) -> Result<(), SessionError> {
        if self.initiator {
            // client -> server
            let mut _msg1 = [0u8; NOISE_HANDSHAKE_MESSAGE1_SIZE];
            let _match = self.session.write_message(&PROLOGUE, &mut _msg1);
            let mut _len = match _match {
                Ok(x) => x,
                Err(_) => return Err(SessionError::ClientHandshakeNoise1Error),
            };
            assert_eq!(NOISE_HANDSHAKE_MESSAGE1_SIZE, _len);

            let mut _match = self.conn_write.as_mut().unwrap().write_all(&_msg1);
            match _match {
                Ok(x) => x,
                Err(_) => return Err(SessionError::ClientHandshakeSend1Error),
            };

            // client <- server
            let mut _msg2 = [0u8; NOISE_HANDSHAKE_MESSAGE2_SIZE];
            let _match = self.conn_read.as_mut().unwrap().read(&mut _msg2);
            _len = match _match {
                Ok(x) => x,
                Err(_) => return Err(SessionError::ClientHandshakeReceiveError),
            };
            assert_eq!(NOISE_HANDSHAKE_MESSAGE2_SIZE, _len);

            let mut _raw_auth = [0u8; AUTH_MESSAGE_SIZE];
            let _match = self.session.read_message(&_msg2, &mut _raw_auth);
            _len = match _match {
                Ok(x) => x,
                Err(_) => return Err(SessionError::ClientHandshakeNoise2Error),
            };
            assert_eq!(NOISE_HANDSHAKE_MESSAGE2_SIZE, _len);

            // convert _raw_auth to AuthenticateMessage
            let auth_msg = authenticate_message_from_bytes(&_raw_auth).unwrap();

            // verify auth info
            {
                let raw_peer_key = self.session.get_remote_static().unwrap();
                let mut peer_key = PublicKey::default();
                peer_key.from_bytes(raw_peer_key);
                let peer_credentials = PeerCredentials {
                    additional_data: auth_msg.additional_data,
                    public_key: peer_key,
                };
                if !self.authenticator.is_peer_valid(&peer_credentials) {
                    return Err(SessionError::ClientAuthenticationError);
                }
            }

            // client -> server
            let mut _msg3 = [0u8; NOISE_HANDSHAKE_MESSAGE3_SIZE];
            let _match = self.session.write_message(&[], &mut _msg3);
            _len = match _match {
                Ok(x) => x,
                Err(_) => return Err(SessionError::ClientHandshakeNoise3Error),
            };
            assert_eq!(NOISE_HANDSHAKE_MESSAGE3_SIZE, _len);
            let mut _match = self.conn_write.as_mut().unwrap().write_all(&_msg3);
            match _match {
                Ok(x) => x,
                Err(_) => return Err(SessionError::ClientHandshakeSend2Error),
            };
        } else {
            // server <-
            let mut _msg1 = [0u8; NOISE_HANDSHAKE_MESSAGE1_SIZE];
            let _match = self.conn_read.as_mut().unwrap().read_exact(&mut _msg1);
            match _match {
                Ok(x) => x,
                Err(_) => return Err(SessionError::ServerHandshakeReceive1Error),
            };

            if _msg1[0..1].ct_eq(&PROLOGUE).unwrap_u8() == 0 {
                return Err(SessionError::ServerPrologueMismatchError);
            }

            let mut _msg1p = [0u8; NOISE_HANDSHAKE_MESSAGE1_SIZE];
            let _match = self.session.read_message(&_msg1, &mut _msg1p);
            let mut _len = match _match {
                Ok(x) => x,
                Err(_) => return Err(SessionError::ServerHandshakeNoise1Error),
            };
            assert_eq!(NOISE_HANDSHAKE_MESSAGE1_SIZE, _len);

            // server ->
            let now = SystemTime::now();
            let our_auth = AuthenticateMessage {
                additional_data: self.additional_data.clone(),
                unix_time: now.elapsed().unwrap().as_secs() as u32,
            };
            let raw_auth = our_auth.to_vec().unwrap();
            let mut _msg2 = [0u8; NOISE_HANDSHAKE_MESSAGE2_SIZE];
            let _match = self.session.write_message(&raw_auth, &mut _msg2);
            let mut _len = match _match {
                Ok(x) => x,
                Err(_) => return Err(SessionError::ServerHandshakeNoise2Error),
            };
            assert_eq!(NOISE_HANDSHAKE_MESSAGE2_SIZE, _len);

            let _match = self.conn_write.as_mut().unwrap().write_all(&_msg2);
            match _match {
                Ok(x) => x,
                Err(_) => return Err(SessionError::ServerHandshakeSendError),
            };

            // server <-
            let mut _msg3 = [0u8; NOISE_HANDSHAKE_MESSAGE3_SIZE];
            let _match = self.conn_read.as_mut().unwrap().read_exact(&mut _msg3);
            match _match {
                Ok(x) => x,
                Err(_) => return Err(SessionError::ServerHandshakeReceive2Error),
            };
            let mut raw_auth = [0u8; AUTH_MESSAGE_SIZE];
            let _match = self.session.read_message(&_msg3, &mut raw_auth);
            match _match {
                Ok(x) => x,
                Err(_) => return Err(SessionError::ServerHandshakeNoise3Error),
            };

            let peer_auth = authenticate_message_from_bytes(&raw_auth).unwrap();
            let raw_peer_key = self.session.get_remote_static().unwrap();
            let mut peer_key = PublicKey::default();
            peer_key.from_bytes(raw_peer_key);
            let peer_credentials = PeerCredentials {
                additional_data: peer_auth.additional_data,
                public_key: peer_key,
            };
            if !self.authenticator.is_peer_valid(&peer_credentials) {
                return Err(SessionError::ServerAuthenticationError);
            }
        }
        return Ok(());
    }

    fn recv_command() -> Result<Box<Command>, SessionError> {
        return Err(SessionError::ServerAuthenticationError); // XXX
    }

    fn finalize_handshake(&mut self) -> Result<(), SessionError> {
        return Ok(()); // XXX
    }
}


#[cfg(test)]
mod tests {

    extern crate mockstream;
    extern crate rustc_serialize;

    use self::rustc_serialize::hex::ToHex;
    use self::mockstream::SyncMockStream;
    use super::*;

    struct NaiveAuthenticator {}
    impl PeerAuthenticator for NaiveAuthenticator {
        fn is_peer_valid(&self, peer_credentials: &PeerCredentials) -> bool {
            return true;
        }
    }

    #[test]
    fn session_handshake_test() {
        // server
        let server_keypair = PrivateKey::generate().unwrap();
        let authenticator = NaiveAuthenticator{};
        let server_keypair = PrivateKey::generate().unwrap();
        let server_config = SessionConfig {
            authenticator: Box::new(authenticator),
            authentication_key: server_keypair,
            peer_public_key: None,
            additional_data: vec![],
        };
        let mut server_session = Session::new(server_config, false).unwrap();

        // client
        let authenticator = NaiveAuthenticator{};
        let client_keypair = PrivateKey::generate().unwrap();
        let client_config = SessionConfig {
            authenticator: Box::new(authenticator),
            authentication_key: client_keypair,
            peer_public_key: Some(server_keypair.public_key()),
            additional_data: vec![],
        };
        let mut client_session = Session::new(client_config, true).unwrap();

        // setup streams
        let mut client_stream = SyncMockStream::new();
        //client_session.initialize(Box::new(client_stream.clone()), Box::new(client_stream.clone())).unwrap();

        // XXX fix me

        // proxy interaction
        // let client_out = client_stream.pop_bytes_written();
        // println!("client -> {}", client_out.to_hex());

        // let mut server_stream = SyncMockStream::new();
        // server_stream.push_bytes_to_read(&client_out);
        // server_session.initialize(Box::new(server_stream.clone()), Box::new(server_stream.clone())).unwrap();

        // let server_out = server_stream.pop_bytes_written();
        // println!("server -> {}", server_out.to_hex());
    }
}
