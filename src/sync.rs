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
extern crate ecdh_wrapper;

use std::net::{TcpStream, Shutdown};
use std::io::prelude::*;

use super::commands::{Command};
use super::errors::{HandshakeError, ReceiveMessageError, SendMessageError};
use super::messages::{MessageFactory, SessionConfig, PeerCredentials};
use super::constants::{NOISE_HANDSHAKE_MESSAGE1_SIZE, NOISE_HANDSHAKE_MESSAGE2_SIZE,
                       NOISE_HANDSHAKE_MESSAGE3_SIZE};


const MAC_LEN: usize = 16;
const MAX_MSG_LEN: usize = 1_048_576;

/// A mixnet link layer protocol session.
pub struct Session {
    reader_tcp_stream: Option<TcpStream>,
    writer_tcp_stream: Option<TcpStream>,
    is_initiator: bool,
    message_factory: MessageFactory,
}

impl Session {

    pub fn new(cfg: SessionConfig, is_initiator: bool) -> Result<Session, HandshakeError> {
        Ok(Session{
            writer_tcp_stream: None,
            reader_tcp_stream: None,
            is_initiator,
            message_factory: MessageFactory::new(cfg, is_initiator)?,
        })
    }

    fn handshake(&mut self) -> Result<(), HandshakeError>{
        let tcp_reader = self.reader_tcp_stream.as_mut().unwrap();
        let tcp_writer = self.writer_tcp_stream.as_mut().unwrap();
        if self.is_initiator {
            // c -> s
            let client_handshake1 = self.message_factory.client_handshake1()?;
            tcp_writer.write_all(&client_handshake1)?;
            self.message_factory.sent_client_handshake1();

            // s -> c
            let mut server_handshake1 = [0; NOISE_HANDSHAKE_MESSAGE2_SIZE];
            tcp_reader.read_exact(&mut server_handshake1)?;
            self.message_factory.received_server_handshake1(server_handshake1)?;

            // c -> s
            let client_handshake2 = self.message_factory.client_handshake2()?;
            tcp_writer.write_all(&client_handshake2)?;
            self.message_factory.sent_client_handshake2();
        } else {
            // c -> s
            let mut client_handshake1 = [0u8; NOISE_HANDSHAKE_MESSAGE1_SIZE];
            tcp_reader.read_exact(&mut client_handshake1)?;
            let server_handshake1 = self.message_factory.received_client_handshake1(client_handshake1).unwrap();

            // s -> c
            tcp_writer.write_all(&server_handshake1)?;
            self.message_factory.sent_server_handshake1();

            // c -> s
            let mut client_handshake2 = [0u8; NOISE_HANDSHAKE_MESSAGE3_SIZE];
            tcp_reader.read_exact(&mut client_handshake2)?;
            self.message_factory.received_client_handshake2(client_handshake2).unwrap();
        }
        Ok(())
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
        self.send_command(&cmd).unwrap();
        Ok(())
    }
        
    pub fn initialize(&mut self, tcp_stream: TcpStream) -> Result<(), HandshakeError>{
        let reader_tcp_stream = tcp_stream.try_clone()?;
        self.reader_tcp_stream = Some(reader_tcp_stream);
        self.writer_tcp_stream = Some(tcp_stream);
        self.handshake()?;
        Ok(())
    }

    pub fn into_transport_mode(self) -> Result<Self, HandshakeError> {
        Ok(Self {
            reader_tcp_stream: self.reader_tcp_stream,
            writer_tcp_stream: self.writer_tcp_stream,
            is_initiator: self.is_initiator,
            message_factory: self.message_factory.into_transport_mode()?,
        })
    }

    pub fn send_command(&mut self, cmd: &Command) -> Result<(), SendMessageError> {
        let ct = cmd.to_vec();
        let ct_len = MAC_LEN + ct.len();
        if ct_len > MAX_MSG_LEN {
            return Err(SendMessageError::InvalidMessageSize);
        }

        let mut to_send = vec![];
        to_send.extend(self.message_factory.encrypt_message(&ct)?);

        // XXX https://github.com/mcginty/snow/issues/35

        self.writer_tcp_stream.as_mut().unwrap().write_all(&to_send)?;
        Ok(())
    }

    pub fn recv_command(&mut self) -> Result<Command, ReceiveMessageError> {
        // Read, decrypt and parse the ciphertext header.
        let mut header_ciphertext = vec![0u8; MAC_LEN + 4];
        self.reader_tcp_stream.as_mut().unwrap().read_exact(&mut header_ciphertext)?;
        let ct_len = self.message_factory.decrypt_message_header(&header_ciphertext.to_vec())?;

        // Read and decrypt the ciphertext.
        let mut ct = vec![0u8; ct_len as usize];
        self.reader_tcp_stream.as_mut().unwrap().read_exact(&mut ct)?;
        let body = self.message_factory.decrypt_message(&ct)?;

        // XXX https://github.com/mcginty/snow/issues/35

        Ok(Command::from_bytes(&body)?)
    }

    pub fn close(&mut self) {
        // XXX https://github.com/mcginty/snow/issues/35
        let _ = self.reader_tcp_stream.as_mut().unwrap().shutdown(Shutdown::Both);
        let _ = self.writer_tcp_stream.as_mut().unwrap().shutdown(Shutdown::Both);
    }

    pub fn peer_credentials(&self) -> &PeerCredentials {
        self.message_factory.peer_credentials()
    }

    pub fn clock_skew(&self) -> u64 {
        self.message_factory.clock_skew()
    }
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
    use super::super::messages::{PeerAuthenticator, ProviderAuthenticatorState, ClientAuthenticatorState};

    #[test]
    fn handshake_test() {
        let mut threads = vec![];
        let server_addr = "127.0.0.1:8000";
        let mut rng = OsRng::new().expect("failure to create an OS RNG");
        let server_keypair = PrivateKey::generate(&mut rng);
        let client_keypair = PrivateKey::generate(&mut rng);

        let mut provider_auth = ProviderAuthenticatorState::default();
        provider_auth.client_map.insert(client_keypair.public_key(), true);
        let provider_authenticator = PeerAuthenticator::Provider(provider_auth);

        let mut client_auth = ClientAuthenticatorState::default();
        client_auth.peer_public_key = server_keypair.public_key();
        let client_authenticator = PeerAuthenticator::Client(client_auth);

        
        // server listener
        threads.push(thread::spawn(move|| {
            let listener = TcpListener::bind(server_addr.clone()).expect("could not start server");

            // server
            let server_config = SessionConfig {
                authenticator: provider_authenticator,
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
                        session.close();
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
            let client_config = SessionConfig {
                authenticator: client_authenticator,
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
            session.close();
        }));

        // wait for spawned threads to exit
        for t in threads {
            let _ = t.join();
        }
    }
}
