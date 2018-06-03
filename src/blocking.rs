// blocking.rs - blocking io interface to noise protocol
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

struct Session {
    is_initiator: bool,
    client_session: Option<ClientSession>,
    server_session: Option<ServerSession>,
    
}

impl Session {
    fn new(is_initiator: bool, config: SessionConfig) -> Session {
        if is_initiator {
            match ClientSession::new(config) {
                Ok(session) => {
                    return Session {
                        is_initiator: is_initiator,
                        client_session: Some(session),
                        server_session: None,
                    };
                },
                Err(_) => fah,
            }
        } else {
            match ClientSession::new(config) {
                Ok(session) => {
                    return Session {
                        is_initiator: is_initiator,
                        client_session: None,
                        server_session: Some(session),
                    };
                },
                Err(_) => fah,
            }            
        }
    }
}
