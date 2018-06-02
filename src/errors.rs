// errors.rs - noise based wire protocol errors
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

use std::error::Error;
use std::fmt;

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
        "I'm a modem error."
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
}

impl fmt::Display for ClientHandshakeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::ClientHandshakeError::*;
        match *self {
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
        }
    }
}

impl Error for ClientHandshakeError {
    fn description(&self) -> &str {
        "I'm a modem error."
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
        }
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
}

impl fmt::Display for ServerHandshakeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::ServerHandshakeError::*;
        match *self {
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
        }
    }
}

impl Error for ServerHandshakeError {
    fn description(&self) -> &str {
        "I'm a modem error."
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
        }
    }
}

#[derive(Debug)]
pub enum SendMessageError {
    InvalidMessageSize,
    EncryptFail,
}

impl fmt::Display for SendMessageError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::SendMessageError::*;
        match *self {
            InvalidMessageSize => write!(f, "Invalid message size."),
            EncryptFail => write!(f, "Failure to encrypt."),
        }
    }
}

impl Error for SendMessageError {
    fn description(&self) -> &str {
        "I'm a modem error."
    }

    fn cause(&self) -> Option<&Error> {
        use self::SendMessageError::*;
        match *self {
            InvalidMessageSize => None,
            EncryptFail => None,
        }
    }
}

#[derive(Debug)]
pub enum ReceiveMessageError {
    InvalidMessageSize,
    DecryptFail,
}

impl fmt::Display for ReceiveMessageError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::ReceiveMessageError::*;
        match *self {
            InvalidMessageSize => write!(f, "Invalid message size."),
            DecryptFail => write!(f, "Failure to encrypt."),
        }
    }
}

impl Error for ReceiveMessageError {
    fn description(&self) -> &str {
        "I'm a modem error."
    }

    fn cause(&self) -> Option<&Error> {
        use self::ReceiveMessageError::*;
        match *self {
            InvalidMessageSize => None,
            DecryptFail => None,
        }
    }
}
