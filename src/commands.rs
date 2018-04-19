// commands.rs - noise based wire protocol commands
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


use byteorder::{ByteOrder, BigEndian};
use std::any::Any;
use sphinxcrypto::constants::{FORWARD_PAYLOAD_SIZE, PAYLOAD_TAG_SIZE, SURB_ID_SIZE, SPHINX_PLAINTEXT_HEADER_SIZE, SURB_SIZE};
use ecdh_wrapper::KEY_SIZE;

const CMD_OVERHEAD: usize = 1 + 1 + 4;

const RETREIVE_MESSAGE_SIZE: usize = 4;
const MESSAGE_BASE_SIZE: usize = 1 + 1 + 4;
const MESSAGE_ACK_SIZE: usize = MESSAGE_BASE_SIZE + SURB_ID_SIZE;
const MESSAGE_MSG_PADDING_SIZE: usize = SURB_ID_SIZE + SPHINX_PLAINTEXT_HEADER_SIZE + SURB_SIZE + PAYLOAD_TAG_SIZE;
const MESSAGE_MSG_SIZE: usize = MESSAGE_BASE_SIZE + MESSAGE_MSG_PADDING_SIZE;
const MESSAGE_EMPTY_SIZE: usize = MESSAGE_ACK_SIZE + PAYLOAD_TAG_SIZE + FORWARD_PAYLOAD_SIZE;

const GET_CONSENSUS_SIZE: usize = 8;
const CONSENSUS_BASE_SIZE: usize = 1;

const POST_DESCRIPTOR_STATUS_SIZE: usize = 1;
const POST_DESCRIPTOR_SIZE: usize = 8;

const PUBLIC_KEY_SIZE: usize = KEY_SIZE;
const VOTE_OVERHEAD: usize = 8 + PUBLIC_KEY_SIZE;
const VOTE_STATUS_SIZE: usize = 1;

const MESSAGE_TYPE_MESSAGE: u8 = 0;
const MESSAGE_TYPE_ACK: u8 = 1;
const MESSAGE_TYPE_EMPTY: u8 = 2;

// Generic wire protocol commands.
const NO_OP: u8 = 0;
const DISCONNECT: u8 = 1;
const SEND_PACKET: u8 = 2;

// Implementation defined commands.
const RETREIVE_MESSAGE: u8 = 16;
const MESSAGE: u8 = 17;
const GET_CONSENSUS: u8 = 18;
const CONSENSUS: u8 = 19;
const POST_DESCRIPTOR: u8 = 20;
const POST_DESCRIPTOR_STATUS: u8 = 21;
const VOTE: u8 = 22;
const VOTE_STATUS: u8 = 23;


pub trait Command {
    fn to_vec(&self) -> Vec<u8>;
}

pub struct NoOp {}

impl Command for NoOp {
    fn to_vec(&self) -> Vec<u8> {
        let mut out = vec![0; CMD_OVERHEAD];
        out[0] = NO_OP;
        out
    }
}

pub struct GetConsensus {
    epoch: u64,
}

impl Command for GetConsensus {
    fn to_vec(&self) -> Vec<u8> {
        let mut out = vec![0; CMD_OVERHEAD+GET_CONSENSUS_SIZE];
        out[0] = NO_OP;
        out
        
    }
}
