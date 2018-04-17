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
pub enum SessionError {
    NoPeerKeyError,
    SessionCreateError,
    InvalidStateError,
    HandshakeError1,
    HandshakeError2,
    HandshakeError3,
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::SessionError::*;
        match *self {
            NoPeerKeyError => write!(f, "No peer key was supplied, error."),
            SessionCreateError => write!(f, "Failure creating session."),
            InvalidStateError => write!(f, "Invalid session state error."),
            HandshakeError1 => write!(f, "Error writing 1st handshake payload."),
            HandshakeError2 => write!(f, "Error writing 2nd handshake payload."),
            HandshakeError3 => write!(f, "Error writing 3rd handshake payload."),
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
            HandshakeError1 => None,
            HandshakeError2 => None,
            HandshakeError3 => None,
        }
    }
}
