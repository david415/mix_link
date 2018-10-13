// sync.rs - synchronous (blocking) IO networking
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

use std::net::TcpStream;
use std::io::prelude::*;
use std::mem;
use byteorder::{ByteOrder, BigEndian};

use super::commands::{Command};
use super::errors::{HandshakeError, ReceiveMessageError, SendMessageError, RekeyError};
use super::messages::{MessageFactory, SessionConfig, PeerAuthenticator};
use super::constants::{NOISE_HANDSHAKE_MESSAGE1_SIZE, NOISE_HANDSHAKE_MESSAGE2_SIZE,
                       NOISE_HANDSHAKE_MESSAGE3_SIZE};


pub const MAX_ADDITIONAL_DATA_LEN: usize = 255;
const MAC_LEN: usize = 16;
const MAX_MSG_LEN: usize = 1048576;
const AUTH_LEN: usize = 1 + MAX_ADDITIONAL_DATA_LEN + 4;



struct Session {
    tcp_stream: Option<TcpStream>,
    is_initiator: bool,
    message_factory: MessageFactory,
}

impl Session {
    pub fn new(cfg: SessionConfig, is_initiator: bool) -> Result<Session, HandshakeError> {
        return Ok(Session{
            tcp_stream: None,
            is_initiator: is_initiator,
            message_factory: MessageFactory::new(cfg, is_initiator)?,
        });
    }

    fn handshake(&mut self) -> Result<(), HandshakeError>{
        if self.is_initiator {
            let tcp_stream = self.tcp_stream.as_mut().unwrap();

            // c -> s
            let client_handshake1 = self.message_factory.client_handshake1()?;
            let _ = tcp_stream.write(&client_handshake1)?;
            self.message_factory.sent_client_handshake1();

            // s -> c
            let mut server_handshake1 = [0; NOISE_HANDSHAKE_MESSAGE2_SIZE];
            tcp_stream.read_exact(&mut server_handshake1)?;
            self.message_factory.received_server_handshake1(server_handshake1)?;

            // c -> s
            let client_handshake2 = self.message_factory.client_handshake2()?;
            tcp_stream.write(&client_handshake2)?;
            self.message_factory.sent_client_handshake2();

            return Ok(());
        } else {
            let tcp_stream = self.tcp_stream.as_mut().unwrap();

            // c -> s
            let mut client_handshake1 = [0u8; NOISE_HANDSHAKE_MESSAGE1_SIZE];
            tcp_stream.read_exact(&mut client_handshake1)?;
            let server_handshake1 = self.message_factory.received_client_handshake1(client_handshake1).unwrap();

            // s -> c
            tcp_stream.write(&server_handshake1)?;
            self.message_factory.sent_server_handshake1();

            // c -> s
            let mut client_handshake2 = [0u8; NOISE_HANDSHAKE_MESSAGE3_SIZE];
            tcp_stream.read_exact(&mut client_handshake2)?;
            self.message_factory.received_client_handshake2(client_handshake2).unwrap();

            return Ok(())
        }
    }

    pub fn finalize_handshake(&mut self) -> Result<(), HandshakeError>{
        if self.is_initiator {
            let cmd = self.recv_command().unwrap();
            match cmd {
                Command::NoOp{} => return Ok(()),
                _ => return Err(HandshakeError::InvalidHandshakeFinalize),
            }
        }
        let cmd = Command::NoOp{};
        self.send_command(cmd).unwrap();
        return Ok(());
    }
        
    /// initialize a link layer session
    ///
    /// # Arguments
    ///
    /// * tcp_stream: A TCP stream.
    ///
    /// # Returns
    ///
    /// * Returns a result.
    pub fn initialize(&mut self, tcp_stream: TcpStream) -> Result<(), HandshakeError>{
        self.tcp_stream = Some(tcp_stream);
        self.handshake()?;
        return Ok(());
    }

    pub fn into_transport_mode(self) -> Result<Self, HandshakeError> {
        Ok(Self {
            tcp_stream: self.tcp_stream,
            is_initiator: self.is_initiator,
            message_factory: self.message_factory.into_transport_mode()?,
        })
    }

    pub fn rekey(&mut self) -> Result<(), RekeyError> {
        self.message_factory.rekey()?;
        Ok(())
    }

    pub fn send_command(&mut self, cmd: Command) -> Result<(), SendMessageError> {
        let ct = cmd.to_vec();
        let ct_len = MAC_LEN + ct.len();
        if ct_len > MAX_MSG_LEN {
            return Err(SendMessageError::InvalidMessageSize);
        }

        let mut to_send = vec![];
        to_send.extend(self.message_factory.encrypt_message(ct)?);

        self.rekey();

        self.tcp_stream.as_mut().unwrap().write(&to_send)?;
        return Ok(())
    }

    pub fn recv_command(&mut self) -> Result<Command, ReceiveMessageError> {
        // Read, decrypt and parse the ciphertext header.
        let mut header_ciphertext = vec![0u8; MAC_LEN + 4];
        self.tcp_stream.as_mut().unwrap().read_exact(&mut header_ciphertext)?;
        let ct_len = self.message_factory.decrypt_message_header(header_ciphertext.to_vec())?;

        // Read and decrypt the ciphertext.
        let mut ct = vec![0u8; ct_len as usize];
        self.tcp_stream.as_mut().unwrap().read_exact(&mut ct)?;
        let body = self.message_factory.decrypt_message(ct)?;

        self.rekey();

        let cmd = Command::from_bytes(&body)?;
        return Ok(cmd);
    }

    pub fn close() {}

    pub fn peer_credentials() {}

    pub fn clock_skew() {}    
}

#[cfg(test)]
mod tests {
    extern crate rand;
    extern crate ecdh_wrapper;

    use std::thread;
    use std::time::Duration;
    use std::net::TcpListener;
    use std::net::TcpStream;
    use self::rand::os::OsRng;
    use ecdh_wrapper::PrivateKey;
    use super::{Session, SessionConfig};
    use super::{PeerAuthenticator};
    use super::super::messages::{PeerCredentials};
    use super::super::commands::{Command};


    struct NaiveAuthenticator {}
    impl PeerAuthenticator for NaiveAuthenticator {
        fn is_peer_valid(&self, _peer_credentials: &PeerCredentials) -> bool {
            return true;
        }
    }

    #[test]
    fn handshake_test() {
        let mut threads = vec![];
        let server_addr = "127.0.0.1:8000";
        let mut rng = OsRng::new().expect("failure to create an OS RNG");
        let server_keypair = PrivateKey::generate(&mut rng).unwrap();
        
        // server listener
        threads.push(thread::spawn(move|| {
            let listener = TcpListener::bind(server_addr.clone()).expect("could not start server");

            // server
            let server_authenticator = NaiveAuthenticator{};
            let server_config = SessionConfig {
                authenticator: Box::new(server_authenticator),
                authentication_key: server_keypair,
                peer_public_key: None,
                additional_data: vec![],
            };
            let mut session = Session::new(server_config, false).unwrap();

            for connection in listener.incoming() {
                match connection {
                    Ok(mut stream) => {
                        session.initialize(stream).unwrap();
                        println!("server handshake completed!");

                        session = session.into_transport_mode().unwrap();
                        session.finalize_handshake().unwrap();
                        return
                    }
                    Err(e) => { println!("connection failed {}", e); }
                }
            }
        }));

        // client dialer
        threads.push(thread::spawn(move|| {
            thread::sleep(Duration::from_secs(1));
            // client
            let client_authenticator = NaiveAuthenticator{};
            let client_keypair = PrivateKey::generate(&mut rng).unwrap();
            let client_config = SessionConfig {
                authenticator: Box::new(client_authenticator),
                authentication_key: client_keypair,
                peer_public_key: Some(server_keypair.public_key()),
                additional_data: vec![],
            };
            let mut session = Session::new(client_config, true).unwrap();

            let stream = TcpStream::connect(server_addr.clone()).expect("connection failed");
            session.initialize(stream).unwrap();
            println!("client handshake completed!");

            session = session.into_transport_mode().unwrap();
            session.finalize_handshake().unwrap();
        }));

        // wait for spawned threads to exit
        for t in threads {
            let _ = t.join();
        }
    }
}
