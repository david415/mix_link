// sessions.rs - client and server protocol sessions
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
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use sphinxcrypto::constants::USER_FORWARD_PAYLOAD_SIZE;

use super::messages::{MessageFactory, MessageFactoryConfig};
use super::errors::{HandshakeError, ReceiveMessageError, SendMessageError};
use super::constants::{NOISE_MESSAGE_HEADER_SIZE, NOISE_HANDSHAKE_MESSAGE1_SIZE,
                       NOISE_HANDSHAKE_MESSAGE2_SIZE, NOISE_HANDSHAKE_MESSAGE3_SIZE};
use super::commands::Command;

pub enum ClientState {
    Init,
    SentHandshake1,
    ReceivedHandshake1,
    DataTransfer,
    Disconnected,
    Invalid,
}

pub struct ClientSession {
    message_factory: MessageFactory,
    state: ClientState,
    output_messages: Vec<Vec<u8>>,
    input_commands: Vec<Command>,
}

impl ClientSession {
    pub fn new(config: MessageFactoryConfig) -> Result<ClientSession, HandshakeError> {
        return Ok(ClientSession {
            message_factory: MessageFactory::new(config, true)?,
            state: ClientState::Init,
            output_messages: Vec::new(),
            input_commands: Vec::new(),
        });
    }

    pub fn initialize(&mut self) -> Result<Vec<u8>, HandshakeError> {
        return Ok(self.message_factory.client_handshake1()?.to_vec());
    }

    pub fn sent_handshake1(&mut self) {
        self.state = ClientState::SentHandshake1;
    }

    pub fn sent_handshake2(&mut self) {
        self.state = ClientState::DataTransfer;
    }

    pub fn handshake2(&mut self) -> Result<Vec<u8>, HandshakeError> {
        return Ok(self.message_factory.client_handshake2()?.to_vec());
    }

    pub fn process_handshake1(&mut self, bytes: Vec<u8>) -> Result<(), HandshakeError> {
        if bytes.len() != NOISE_HANDSHAKE_MESSAGE2_SIZE {
            return Err(HandshakeError::InvalidStateError)
        }
        let mut message = [0u8; NOISE_HANDSHAKE_MESSAGE2_SIZE];
        message.copy_from_slice(&bytes);
        self.message_factory.client_read_handshake1(message)?;
        self.state = ClientState::ReceivedHandshake1;
        return Ok(());
    }

    pub fn encrypt_message(&mut self, plaintext: Vec<u8>) -> Result<Vec<u8>, SendMessageError> {
        return Ok(self.message_factory.encrypt_message(plaintext)?);
    }

    pub fn decrypt_message(&mut self, ciphertext: Vec<u8>) -> Result<Vec<u8>, ReceiveMessageError> {
        let ciphertext_len = ciphertext.len();
        let message_size = self.message_factory.decrypt_message_header(ciphertext.clone())?;
        if (ciphertext_len - NOISE_MESSAGE_HEADER_SIZE) as u32 != message_size {
            return Err(ReceiveMessageError::InvalidMessageSize);
        }
        return Ok(self.message_factory.decrypt_message(ciphertext[NOISE_MESSAGE_HEADER_SIZE..].to_vec())?);
    }

    pub fn received(&mut self, message: Vec<u8>) -> Result<(), HandshakeError> {
        match self.state {
            ClientState::SentHandshake1 => {
                self.process_handshake1(message)?;
                return Ok(());
            },
            ClientState::DataTransfer => {
                let cmd_bytes = match self.decrypt_message(message) {
                    Ok(x) => x,
                    Err(_) => {
                        return Err(HandshakeError::InvalidStateError);
                    }, // XXX
                };
                match Command::from_bytes(&cmd_bytes) {
                    Ok(cmd) => self.input_commands.push(cmd),
                    Err(_) => {
                        return Err(HandshakeError::InvalidStateError);
                    }, // XXX
                }
                return Ok(());
            },
            _ => return Err(HandshakeError::InvalidStateError),
        }
    }
}

pub enum ServerState {
    Init,
    ReceivedHandshake1,
    SentHandshake1,
    DataTransfer,
    Disconnected,
    Invalid,
}

pub struct ServerSession {
    message_factory: MessageFactory,
    state: ServerState,
    output_messages: Vec<Vec<u8>>,
    input_commands: Vec<Command>,
}

impl ServerSession {
    pub fn new(config: MessageFactoryConfig) -> Result<ServerSession, HandshakeError> {
        return Ok(ServerSession {
            message_factory: MessageFactory::new(config, false)?,
            state: ServerState::Init,
            output_messages: Vec::new(),
            input_commands: Vec::new(),
        });
    }

    pub fn get_output_message(&mut self) -> Vec<u8> {
        return self.output_messages.pop().unwrap();
    }

    pub fn received(&mut self, message: Vec<u8>) -> Result<(), HandshakeError> {
        match self.state {
            ServerState::Init => {
                let to_send = self.process_handshake1(message)?;
                self.output_messages.push(to_send);
                return Ok(());
            },
            ServerState::SentHandshake1 => {
                self.process_handshake2(message)?;
                return Ok(());
            },
            ServerState::DataTransfer => {
                let cmd_bytes = match self.decrypt_message(message) {
                    Ok(x) => x,
                    Err(_) => return Err(HandshakeError::InvalidStateError), // XXX
                };
                match Command::from_bytes(&cmd_bytes) {
                    Ok(cmd) => self.input_commands.push(cmd),
                    Err(_) => return Err(HandshakeError::InvalidStateError), // XXX
                }
                return Ok(());
            },
            _ => return Err(HandshakeError::InvalidStateError), // XXX
        }
    }

    pub fn process_handshake1(&mut self, bytes: Vec<u8>) -> Result<Vec<u8>, HandshakeError> {
        if bytes.len() != NOISE_HANDSHAKE_MESSAGE1_SIZE {
            return Err(HandshakeError::InvalidStateError)
        }
        let mut message = [0u8; NOISE_HANDSHAKE_MESSAGE1_SIZE];
        message.copy_from_slice(&bytes);
        self.message_factory.server_read_handshake1(message)?;
        let to_send = self.message_factory.server_handshake1()?;
        self.state = ServerState::ReceivedHandshake1;
        return Ok(to_send.to_vec())
    }

    pub fn sent_handshake1(&mut self) {
        self.state = ServerState::SentHandshake1;
    }

    pub fn process_handshake2(&mut self, bytes: Vec<u8>) -> Result<(), HandshakeError> {
        if bytes.len() != NOISE_HANDSHAKE_MESSAGE3_SIZE {
            return Err(HandshakeError::InvalidStateError)
        }
        let mut message = [0u8; NOISE_HANDSHAKE_MESSAGE3_SIZE];
        message.copy_from_slice(&bytes);
        self.message_factory.server_read_handshake2(message)?;
        self.state = ServerState::DataTransfer;
        return Ok(());
    }

    pub fn decrypt_message(&mut self, ciphertext: Vec<u8>) -> Result<Vec<u8>, ReceiveMessageError> {
        let ciphertext_len = ciphertext.len();
        let message_size = self.message_factory.decrypt_message_header(ciphertext.clone())?;
        if (ciphertext_len - NOISE_MESSAGE_HEADER_SIZE) as u32 != message_size {
            return Err(ReceiveMessageError::InvalidMessageSize);
        }
        return Ok(self.message_factory.decrypt_message(ciphertext[NOISE_MESSAGE_HEADER_SIZE..].to_vec())?);
    }

    pub fn encrypt_message(&mut self, plaintext: Vec<u8>) -> Result<Vec<u8>, SendMessageError> {
        return Ok(self.message_factory.encrypt_message(plaintext)?);
    }
}

#[cfg(test)]
mod tests {
    extern crate rand;
    extern crate ecdh_wrapper;
    extern crate rustc_serialize;

    use self::rustc_serialize::hex::ToHex;
    use self::rand::os::OsRng;
    use ecdh_wrapper::PrivateKey;

    use super::*;
    use super::super::messages::{MessageFactoryConfig, PeerAuthenticator, PeerCredentials};

    struct NaiveAuthenticator {}
    impl PeerAuthenticator for NaiveAuthenticator {
        fn is_peer_valid(&self, _peer_credentials: &PeerCredentials) -> bool {
            return true;
        }
    }

    #[test]
    fn session_handshake_test() {
        let mut r = OsRng::new().expect("failure to create an OS RNG");

        // server
        let server_authenticator = NaiveAuthenticator{};
        let server_keypair = PrivateKey::generate(&mut r).unwrap();
        let server_config = MessageFactoryConfig {
            authenticator: Box::new(server_authenticator),
            authentication_key: server_keypair,
            peer_public_key: None,
            additional_data: vec![],
        };
        let mut server_session = ServerSession::new(server_config).unwrap();

        // client
        let client_authenticator = NaiveAuthenticator{};
        let client_keypair = PrivateKey::generate(&mut r).unwrap();
        let client_config = MessageFactoryConfig {
            authenticator: Box::new(client_authenticator),
            authentication_key: client_keypair,
            peer_public_key: Some(server_keypair.public_key()),
            additional_data: vec![],
        };
        let mut client_session = ClientSession::new(client_config).unwrap();

        // handshake
        // c -> s
        let client_handshake1 = client_session.initialize().unwrap();
        client_session.sent_handshake1();
        server_session.received(client_handshake1).unwrap();

        // s -> c
        let server_handshake1 = server_session.get_output_message();
        server_session.sent_handshake1();
        client_session.received(server_handshake1).unwrap();

        // c -> s
        let client_handshake2 = client_session.handshake2().unwrap();
        client_session.sent_handshake2();
        server_session.received(client_handshake2).unwrap();

        // data transfer phase
        server_session.message_factory = server_session.message_factory.data_transfer().unwrap();
        client_session.message_factory = client_session.message_factory.data_transfer().unwrap();

        // s -> c
        let server_cmd = Command::MessageMessage {
            queue_size_hint: 0u8,
            sequence: 0u32,
            payload: vec![0u8; USER_FORWARD_PAYLOAD_SIZE],
        };
        let server_message = server_cmd.clone().to_vec();
        let to_send = server_session.encrypt_message(server_message).unwrap();
        client_session.received(to_send).unwrap();
        assert_eq!(server_cmd, client_session.input_commands[0]);

        let client_cmd = Command::NoOp{};
        let client_message = client_cmd.clone().to_vec();
        let client_to_send = client_session.encrypt_message(client_message).unwrap();
        server_session.received(client_to_send).unwrap();
        assert_eq!(client_cmd, server_session.input_commands[0]);
    }
}
