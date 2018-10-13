// errors.rs - noise based wire protocol errors
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

use std::error::{Error};
use std::fmt;
use std::io::{self};

use snow::SnowError;

#[derive(Debug)]
pub enum RekeyError {
    Wtf,
    SnowError(SnowError),

}

impl fmt::Display for RekeyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::RekeyError::*;
        match self {
            Wtf => write!(f, "wtf."),
            SnowError(x) => x.fmt(f),
        }
    }
}


impl Error for RekeyError {
    fn description(&self) -> &str {
        "I'm a command error."
    }

    fn cause(&self) -> Option<&Error> {
        use self::RekeyError::*;
        match self {
            Wtf => None,
            SnowError(x) => self.cause(),
        }
    }
}

impl From<SnowError> for RekeyError {
    fn from(error: snow::SnowError) -> Self {
        RekeyError::SnowError(error)
    }
}



#[derive(Debug)]
pub enum CommandError {
    InvalidNoiseSpecError,
    InvalidLengthError,
    InvalidReservedByte,
    TooSmallError,
    GetConsensusDecodeError,
    ConsensusDecodeError,

    PostDescriptorDecodeError,
    PostDescriptorStatusDecodeError,
    VoteDecodeError,
    VoteStatusDecodeError,
    RetreiveMessageDecodeError,
    MessageDecodeError,
    InvalidMessageType,
    InvalidStateError,
}

impl fmt::Display for CommandError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::CommandError::*;
        match *self {
            InvalidNoiseSpecError => write!(f, "Invalid noise protocol string."),
            InvalidLengthError => write!(f, "Invalid length."),
            InvalidReservedByte => write!(f, "Reserved byte is invalid."),
            TooSmallError => write!(f, "Command is too small."),
            GetConsensusDecodeError => write!(f, "Failed to decode a Get Consensus command."),
            ConsensusDecodeError => write!(f, "Failed to decode a Consensus command."),
            PostDescriptorDecodeError => write!(f, "Failed to decode a PostDescriptor command."),
            PostDescriptorStatusDecodeError => write!(f, "Failed to decode a PostDescriptor command."),
            VoteDecodeError => write!(f, "Failed to decode a Vote command."),
            VoteStatusDecodeError => write!(f, "Failed to decode a VoteStatus command."),
            RetreiveMessageDecodeError => write!(f, "Failed to decode a RetreiveMessage command."),
            MessageDecodeError => write!(f, "Failed to decode a Message command."),
            InvalidMessageType => write!(f, "Failed to decode a Message command with invalid type."),
            InvalidStateError => write!(f, "Encountered invalid state transition."),
        }
    }
}

impl Error for CommandError {
    fn description(&self) -> &str {
        "I'm a command error."
    }

    fn cause(&self) -> Option<&Error> {
        use self::CommandError::*;
        match *self {
            InvalidNoiseSpecError => None,
            InvalidLengthError => None,
            InvalidReservedByte => None,
            TooSmallError => None,
            GetConsensusDecodeError => None,
            ConsensusDecodeError => None,
            PostDescriptorDecodeError => None,
            PostDescriptorStatusDecodeError => None,
            VoteDecodeError => None,
            VoteStatusDecodeError => None,
            RetreiveMessageDecodeError => None,
            MessageDecodeError => None,
            InvalidMessageType => None,
            InvalidStateError => None,
        }
    }
}

#[derive(Debug)]
pub enum ClientHandshakeError {
    InvalidNoiseSpecError,
    NoPeerKeyError,
    SessionCreateError,
    Noise1WriteError,
    Noise2ReadError,
    Noise3WriteError,
    SentHandshake1InvalidState,
    InitiateDataTransferError,
    AuthenticationError,
    FailedToGetRemoteStatic,
    FailedToDecodeRemoteStatic,
    InvalidStateError,
    SnowError(SnowError),
}

impl fmt::Display for ClientHandshakeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::ClientHandshakeError::*;
        match self {
            InvalidNoiseSpecError => write!(f, "Invalid noise protocol string."),
            NoPeerKeyError => write!(f, "No peer key was supplied."),
            SessionCreateError => write!(f, "Session creation failure."),
            Noise1WriteError => write!(f, "Failed to write first noise handshake message."),
            Noise2ReadError => write!(f, "Failed to read second noise handshake message."),
            Noise3WriteError => write!(f, "Failed to write third noise handshake message."),
            SentHandshake1InvalidState => write!(f, "SentHandshake1 called for an invalid state."),
            InitiateDataTransferError => write!(f, "Initiate Data Transfer called for an invalid state."),
            AuthenticationError => write!(f, "Invalid authentication received."),
            FailedToGetRemoteStatic => write!(f, "Failed to get remote static key."),
            FailedToDecodeRemoteStatic => write!(f, "Failed to decode remote static key."),
            InvalidStateError => write!(f, "Invalid state transition."),
            SnowError(x) => x.fmt(f),
        }
    }
}

impl Error for ClientHandshakeError {
    fn description(&self) -> &str {
        "I'm a client handshake error."
    }

    fn cause(&self) -> Option<&Error> {
        use self::ClientHandshakeError::*;
        match *self {
            InvalidNoiseSpecError => None,
            NoPeerKeyError => None,
            SessionCreateError => None,
            Noise1WriteError => None,
            Noise2ReadError => None,
            Noise3WriteError => None,
            SentHandshake1InvalidState => None,
            InitiateDataTransferError => None,
            AuthenticationError => None,
            FailedToGetRemoteStatic => None,
            FailedToDecodeRemoteStatic => None,
            InvalidStateError => None,
            SnowError(_) => None,
        }
    }
}

impl From<SnowError> for ClientHandshakeError {
    fn from(error: snow::SnowError) -> Self {
        ClientHandshakeError::SnowError(error)
    }
}


#[derive(Debug)]
pub enum ServerHandshakeError {
    PrologueMismatchError,
    InvalidNoiseSpecError,
    NoPeerKeyError,
    SessionCreateError,
    Noise1ReadError,
    Noise2WriteError,
    Noise3ReadError,
    SentHandshake1InvalidState,
    InitiateDataTransferError,
    AuthenticationError,
    FailedToGetRemoteStatic,
    FailedToDecodeRemoteStatic,
    InvalidStateError,
    SnowError(SnowError),
}

impl fmt::Display for ServerHandshakeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::ServerHandshakeError::*;
        match self {
            PrologueMismatchError => write!(f, "Prologue mismatch error."),
            InvalidNoiseSpecError => write!(f, "Invalid noise protocol string."),
            NoPeerKeyError => write!(f, "No peer key was supplied."),
            SessionCreateError => write!(f, "Session creation failure."),
            Noise1ReadError => write!(f, "Failed to write first noise handshake message."),
            Noise2WriteError => write!(f, "Failed to read second noise handshake message."),
            Noise3ReadError => write!(f, "Failed to write third noise handshake message."),
            SentHandshake1InvalidState => write!(f, "SentHandshake1 called for an invalid state."),
            InitiateDataTransferError => write!(f, "Initiate Data Transfer called for an invalid state."),
            AuthenticationError => write!(f, "Invalid authentication received."),
            FailedToGetRemoteStatic => write!(f, "Failed to get remote static key."),
            FailedToDecodeRemoteStatic => write!(f, "Failed to decode remote static key."),
            InvalidStateError => write!(f, "Invalid state transition."),
            SnowError(x) => x.fmt(f),
        }
    }
}

impl Error for ServerHandshakeError {
    fn description(&self) -> &str {
        "I'm a server handshake error."
    }

    fn cause(&self) -> Option<&Error> {
        use self::ServerHandshakeError::*;
        match *self {
            PrologueMismatchError => None,
            InvalidNoiseSpecError => None,
            NoPeerKeyError => None,
            SessionCreateError => None,
            Noise1ReadError => None,
            Noise2WriteError => None,
            Noise3ReadError => None,
            SentHandshake1InvalidState => None,
            InitiateDataTransferError => None,
            AuthenticationError => None,
            FailedToGetRemoteStatic => None,
            FailedToDecodeRemoteStatic => None,
            InvalidStateError => None,
            SnowError(_) => None,
        }
    }
}


impl From<SnowError> for ServerHandshakeError {
    fn from(error: SnowError) -> Self {
        ServerHandshakeError::SnowError(error)
    }
}

#[derive(Debug)]
pub enum HandshakeError {
    InvalidNoiseSpecError,
    NoPeerKeyError,
    SessionCreateError,
    ClientHandshakeError(ClientHandshakeError),
    ServerHandshakeError(ServerHandshakeError),
    InvalidStateError,
    InvalidHandshakeFinalize,
    IOError(io::Error),
    SnowError(snow::SnowError),
    ReceiveMessageError(ReceiveMessageError),
    SendMessageError(SendMessageError),
}

impl fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::HandshakeError::*;
        match self {
            InvalidNoiseSpecError => write!(f, "Invalid noise protocol string."),
            NoPeerKeyError => write!(f, "No peer key was supplied."),
            SessionCreateError => write!(f, "Session creation failure."),
            ClientHandshakeError(x) => x.fmt(f),
            ServerHandshakeError(x) => x.fmt(f),
            InvalidHandshakeFinalize => write!(f, "Invalid command received from handshake finalization."),
            InvalidStateError => write!(f, "Impossible error like this should never happen."),
            _ => write!(f, "Impossible error like this should never happen."),
        }
    }
}

impl Error for HandshakeError {
    fn description(&self) -> &str {
        "I'm a handshake error."
    }

    fn cause(&self) -> Option<&Error> {
        use self::HandshakeError::*;
        match self {
            InvalidNoiseSpecError => None,
            NoPeerKeyError => None,
            SessionCreateError => None,
            ClientHandshakeError(x) => x.cause(),
            ServerHandshakeError(x) => x.cause(),
            InvalidStateError => None,
            IOError(x) => x.cause(),
            SnowError(_) => None,
            ReceiveMessageError(x) => x.cause(),
            SendMessageError(x) => x.cause(),
            InvalidHandshakeFinalize => None,
        }
    }
}

impl From<SendMessageError> for HandshakeError {
    fn from(error: SendMessageError) -> Self {
        HandshakeError::SendMessageError(error)
    }
}

impl From<ReceiveMessageError> for HandshakeError {
    fn from(error: ReceiveMessageError) -> Self {
        HandshakeError::ReceiveMessageError(error)
    }
}

impl From<ClientHandshakeError> for HandshakeError {
    fn from(error: ClientHandshakeError) -> Self {
        HandshakeError::ClientHandshakeError(error)
    }
}

impl From<ServerHandshakeError> for HandshakeError {
    fn from(error: ServerHandshakeError) -> Self {
        HandshakeError::ServerHandshakeError(error)
    }
}

impl From<io::Error> for HandshakeError {
    fn from(error: io::Error) -> Self {
        HandshakeError::IOError(error)
    }
}

impl From<snow::SnowError> for HandshakeError {
    fn from(error: snow::SnowError) -> Self {
        HandshakeError::SnowError(error)
    }
}


#[derive(Debug)]
pub enum SendMessageError {
    InvalidMessageSize,
    EncryptFail,
    RekeyError(RekeyError),
    IOError(io::Error),
}

impl fmt::Display for SendMessageError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::SendMessageError::*;
        match self {
            InvalidMessageSize => write!(f, "Invalid message size."),
            EncryptFail => write!(f, "Failure to encrypt."),
            IOError(ref x) => x.fmt(f),
            RekeyError(x) => x.fmt(f),
        }
    }
}

impl Error for SendMessageError {
    fn description(&self) -> &str {
        "I'm a send message error."
    }

    fn cause(&self) -> Option<&Error> {
        use self::SendMessageError::*;
        match self {
            InvalidMessageSize => None,
            EncryptFail => None,
            IOError(_) => None,
            RekeyError(x) => x.cause(),
        }
    }
}

impl From<io::Error> for SendMessageError {
    fn from(error: io::Error) -> Self {
        SendMessageError::IOError(error)
    }
}

impl From<RekeyError> for SendMessageError {
    fn from(error: RekeyError) -> Self {
        SendMessageError::RekeyError(error)
    }
}


#[derive(Debug)]
pub enum ReceiveMessageError {
    InvalidMessageSize,
    DecryptFail,
    CommandError(CommandError),
    IOError(io::Error),
    RekeyError(RekeyError),
}

impl fmt::Display for ReceiveMessageError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::ReceiveMessageError::*;
        match self {
            InvalidMessageSize => write!(f, "Invalid message size."),
            DecryptFail => write!(f, "Failure to encrypt."),
            CommandError(x) => x.fmt(f),
            IOError(ref x) => x.fmt(f),
            RekeyError(x) => x.fmt(f),
        }
    }
}

impl Error for ReceiveMessageError {
    fn description(&self) -> &str {
        "I'm a receive message error."
    }

    fn cause(&self) -> Option<&Error> {
        use self::ReceiveMessageError::*;
        match self {
            InvalidMessageSize => None,
            DecryptFail => None,
            CommandError(_) => None,
            IOError(_) => None,
            RekeyError(x) => x.cause(),
        }
    }
}

impl From<RekeyError> for ReceiveMessageError {
    fn from(error: RekeyError) -> Self {
        ReceiveMessageError::RekeyError(error)
    }
}

impl From<CommandError> for ReceiveMessageError {
    fn from(error: CommandError) -> Self {
        ReceiveMessageError::CommandError(error)
    }
}

impl From<io::Error> for ReceiveMessageError {
    fn from(error: io::Error) -> Self {
        ReceiveMessageError::IOError(error)
    }
}
