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

use snow::params::NoiseParams;
use snow::NoiseBuilder;
use ecdh_wrapper::{PrivateKey, PublicKey};
use super::error::SessionError;


pub const NOISE_PARAMS: &'static str = "Noise_XX_25519_ChaChaPoly_BLAKE2b";
pub const PROLOGUE: [u8;1] = [0u8;1];


pub struct PeerCredentials {
    pub additional_data: Vec<u8>,
    pub public_key: PublicKey,
}

pub trait PeerAuthenticator {
    fn is_peer_valid(&self, peer_credentials: &PeerCredentials) -> bool;
}

pub struct Session {
    initiator: bool,
    session: snow::Session,
    authentication_key: PrivateKey,
}

pub struct SessionConfig {
    pub authenticator: Box<PeerAuthenticator>,
    pub authentication_key: PrivateKey,
    pub peer_public_key: Option<PublicKey>,
    pub additional_data: Vec<u8>,
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
                .remote_public_key(&(session_config.peer_public_key.expect("peer key")).to_vec())
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
        };
        Ok(_s)
    }
}
