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

use std::net::TcpStream;
use std::io::{Write, Read};
use snow::params::NoiseParams;
use snow::NoiseBuilder;
use ecdh_wrapper::{PrivateKey, PublicKey};

use super::error::SessionError;


const NOISE_PARAMS: &'static str = "Noise_XX_25519_ChaChaPoly_BLAKE2b";
const PROLOGUE: [u8;1] = [0u8;1];
const NOISE_MESSAGE_MAX_SIZE: usize = 65535;

const NOISE_HANDSHAKE_MESSAGE1_SIZE: usize = 32;
const NOISE_HANDSHAKE_MESSAGE2_SIZE: usize = 96;


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
    authentication_key: PrivateKey,
    state: SessionState,
    conn_write: Option<Box<Write>>,
    conn_read: Option<Box<Read>>,
    _buf: [u8; NOISE_MESSAGE_MAX_SIZE],
    _payload: [u8; NOISE_MESSAGE_MAX_SIZE],
}

impl Session {
    pub fn new(session_config: &SessionConfig, is_initiator: bool) -> Result<Session, SessionError> {
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
        let _s = Session {
            initiator: is_initiator,
            authentication_key: session_config.authentication_key,
            session: _session,
            _buf: [0u8; NOISE_MESSAGE_MAX_SIZE],
            _payload: [0u8; NOISE_MESSAGE_MAX_SIZE],
            conn_read: None,
            conn_write: None,
            state: SessionState::Init,
        };
        Ok(_s)
    }

    pub fn initialize(&mut self, conn_read: Box<Read>, conn_write: Box<Write>) -> Result<(), SessionError> {
        if self.state != SessionState::Init {
            return Err(SessionError::InvalidStateError);
        }
        self.conn_read = Some(conn_read);
        self.conn_write = Some(conn_write);
        self.handshake().unwrap(); // XXX

        return Ok(());
    }

    pub fn handshake(&mut self) -> Result<(), SessionError> {
        if self.initiator {
            let _match = self.session.write_message(&[], &mut self._buf);
            let mut _len = match _match {
                Ok(x) => x,
                Err(_) => return Err(SessionError::HandshakeError1),
            };
            let mut _match = self.conn_write.as_mut().unwrap().write_all(&self._buf[.._len]);
            match _match {
                Ok(x) => x,
                Err(_) => return Err(SessionError::HandshakeError2),
            };

            _len = self.conn_read.as_mut().unwrap().read(&mut self._buf).unwrap();
            println!("client read {} bytes", _len);
            //let _len = self.session.read_message(&self._buf[..NOISE_HANDSHAKE_MESSAGE2_SIZE], &mut self._payload).unwrap();


        } else {
            if !self.conn_read.as_mut().is_some() {
                return Err(SessionError::HandshakeError3);
            }

            self.conn_read.as_mut().unwrap().read_exact(&mut self._buf[..NOISE_HANDSHAKE_MESSAGE1_SIZE]).unwrap();
            self.session.read_message(&self._buf[..NOISE_HANDSHAKE_MESSAGE1_SIZE], &mut self._payload).unwrap();

            let server_len = self.session.write_message(&[], &mut self._payload).unwrap();
            println!("server write len {}", server_len);
            self.conn_write.as_mut().unwrap().write_all(&self._payload[..server_len]).unwrap();
        }
        return Ok(());
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
        let mut server_session = Session::new(&server_config, false).unwrap();

        // client
        let authenticator = NaiveAuthenticator{};
        let client_keypair = PrivateKey::generate().unwrap();
        let client_config = SessionConfig {
            authenticator: Box::new(authenticator),
            authentication_key: client_keypair,
            peer_public_key: Some(server_keypair.public_key()),
            additional_data: vec![],
        };
        let mut client_session = Session::new(&client_config, true).unwrap();

        // setup streams
        let mut client_stream = SyncMockStream::new();
        client_session.initialize(Box::new(client_stream.clone()), Box::new(client_stream.clone())).unwrap();

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
