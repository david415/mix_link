// error.rs - noise based wire protocol errors
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

use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub enum CommandError {
    GetConsensusDecodeError,
    ConsensusDecodeError,
    PostDescriptorDecodeError,
    PostDescriptorStatusDecodeError,
    VoteDecodeError,
    VoteStatusDecodeError,
    RetreiveMessageDecodeError,
    MessageDecodeError,
    InvalidMessageType,
}

impl fmt::Display for CommandError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::CommandError::*;
        match *self {
            GetConsensusDecodeError => write!(f, "Failed to decode a Get Consensus command."),
            ConsensusDecodeError => write!(f, "Failed to decode a Consensus command."),
            PostDescriptorDecodeError => write!(f, "Failed to decode a PostDescriptor command."),
            PostDescriptorStatusDecodeError => write!(f, "Failed to decode a PostDescriptor command."),
            VoteDecodeError => write!(f, "Failed to decode a Vote command."),
            VoteStatusDecodeError => write!(f, "Failed to decode a VoteStatus command."),
            RetreiveMessageDecodeError => write!(f, "Failed to decode a RetreiveMessage command."),
            MessageDecodeError => write!(f, "Failed to decode a Message command."),
            InvalidMessageType => write!(f, "Failed to decode a Message command with invalid type."),
        }
    }
}


impl Error for CommandError {
    fn description(&self) -> &str {
        "I'm a modem error."
    }

    fn cause(&self) -> Option<&Error> {
        use self::CommandError::*;
        match *self {
            GetConsensusDecodeError => None,
            ConsensusDecodeError => None,
            PostDescriptorDecodeError => None,
            PostDescriptorStatusDecodeError => None,
            VoteDecodeError => None,
            VoteStatusDecodeError => None,
            RetreiveMessageDecodeError => None,
            MessageDecodeError => None,
            InvalidMessageType => None,
        }
    }
}


#[derive(Debug)]
pub enum SessionError {
    NoPeerKeyError,
    SessionCreateError,
    InvalidStateError,
    ClientHandshakeNoise1Error,
    ClientHandshakeNoise2Error,
    ClientHandshakeNoise3Error,
    ClientHandshakeSend1Error,
    ClientHandshakeSend2Error,
    ClientHandshakeReceiveError,
    ClientAuthenticationError,
    ServerHandshakeReceive1Error,
    ServerHandshakeReceive2Error,
    ServerHandshakeSendError,
    ServerHandshakeNoise1Error,
    ServerHandshakeNoise2Error,
    ServerHandshakeNoise3Error,
    ServerPrologueMismatchError,
    ServerAuthenticationError,
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::SessionError::*;
        match *self {
            NoPeerKeyError => write!(f, "No peer key was supplied, error."),
            SessionCreateError => write!(f, "Failure creating session."),
            InvalidStateError => write!(f, "Invalid session state error."),
            ClientHandshakeNoise1Error => write!(f, "Error preparing client handshake payload."),
            ClientHandshakeNoise2Error => write!(f, "Error preparing client handshake payload."),
            ClientHandshakeNoise3Error => write!(f, "Error preparing client handshake payload."),
            ClientHandshakeSend1Error => write!(f, "Error sending client handshake payload."),
            ClientHandshakeSend2Error => write!(f, "Error sending client handshake payload."),
            ClientHandshakeReceiveError => write!(f, "Error receiving client handshake payload."),
            ClientAuthenticationError => write!(f, "Error authenticating peer."),
            ServerHandshakeNoise1Error => write!(f, "Error preparing server handshake payload."),
            ServerHandshakeNoise2Error => write!(f, "Error preparing server handshake payload."),
            ServerHandshakeNoise3Error => write!(f, "Error preparing server handshake payload."),
            ServerHandshakeSendError => write!(f, "Error sending server handshake payload."),
            ServerHandshakeReceive1Error => write!(f, "Error receiving server handshake payload."),
            ServerHandshakeReceive2Error => write!(f, "Error receiving server handshake payload."),
            ServerPrologueMismatchError => write!(f, "Error server received wrong prologue from client."),
            ServerAuthenticationError => write!(f, "Error server failed to authenticate client."),
        }
    }
}


impl Error for SessionError {
    fn description(&self) -> &str {
        "I'm a modem error."
    }

    fn cause(&self) -> Option<&Error> {
        use self::SessionError::*;
        match *self {
            NoPeerKeyError => None,
            SessionCreateError => None,
            InvalidStateError => None,
            ClientHandshakeNoise1Error => None,
            ClientHandshakeNoise2Error => None,
            ClientHandshakeNoise3Error => None,
            ClientHandshakeSend1Error => None,
            ClientHandshakeSend2Error => None,
            ClientHandshakeReceiveError => None,
            ClientAuthenticationError => None,
            ServerHandshakeNoise1Error => None,
            ServerHandshakeNoise2Error => None,
            ServerHandshakeNoise3Error => None,
            ServerHandshakeSendError => None,
            ServerHandshakeReceive1Error => None,
            ServerHandshakeReceive2Error => None,
            ServerPrologueMismatchError => None,
            ServerAuthenticationError => None,
        }
    }
}
