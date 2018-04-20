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
use ecdh_wrapper::{KEY_SIZE, PublicKey};

use sphinxcrypto::constants::{FORWARD_PAYLOAD_SIZE,
                              PAYLOAD_TAG_SIZE,
                              SURB_ID_SIZE,
                              SPHINX_PLAINTEXT_HEADER_SIZE,
                              SURB_SIZE,
                              USER_FORWARD_PAYLOAD_SIZE};

use super::error::CommandError;

const CMD_OVERHEAD: usize = 1 + 1 + 4;

const RETRIEVE_MESSAGE_SIZE: usize = 4;
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
const RETRIEVE_MESSAGE: u8 = 16;
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

fn get_consensus_from_bytes(b: &[u8]) -> Result<GetConsensus, CommandError> {
    if b.len() != GET_CONSENSUS_SIZE {
        return Err(CommandError::GetConsensusDecodeError);
    }
    return Ok(GetConsensus{
        epoch: BigEndian::read_u64(&b[..8]),
    });
}

pub struct Consensus {
    error_code: u8,
    payload: Vec<u8>,
}

impl Command for Consensus {
    fn to_vec(&self) -> Vec<u8> {
        let consensus_size: usize = CONSENSUS_BASE_SIZE + self.payload.len();
        let mut out = vec![];
        out.push(CONSENSUS);
        let mut _len_raw = [0u8; 4];
        BigEndian::write_u32(&mut _len_raw[2..6], consensus_size as u32);
        out.extend_from_slice(&_len_raw);
        out.push(self.error_code);
        out.extend_from_slice(&self.payload);
        return out;
    }
}

fn consensus_from_bytes(b: &[u8]) -> Result<Consensus, CommandError> {
    if b.len() < CONSENSUS_BASE_SIZE {
        return Err(CommandError::ConsensusDecodeError);
    }
    let _payload_len = (b.len() - CONSENSUS_BASE_SIZE) as u8;
    let mut _payload: Vec<u8> = vec![];
    if _payload_len > 0 {
        _payload.push(_payload_len);
        _payload.extend_from_slice(&b[CONSENSUS_BASE_SIZE..]);
    }
    return Ok(Consensus {
        error_code: b[0],
        payload: _payload,
    });
}

pub struct PostDescriptor {
    epoch: u64,
    payload: Vec<u8>,
}

impl Command for PostDescriptor {
    fn to_vec(&self) -> Vec<u8> {
        let mut out = vec![];
        out.push(POST_DESCRIPTOR);
        let mut _desc_len = [0u8; 4];
        BigEndian::write_u32(&mut _desc_len, POST_DESCRIPTOR_SIZE as u32 + self.payload.len() as u32);
        out.extend_from_slice(&_desc_len);
        let mut _epoch = [0u8; 8];
        BigEndian::write_u64(&mut _epoch, self.epoch);
        out.extend_from_slice(&_epoch);
        out.extend_from_slice(&self.payload);
        return out;
    }
}

fn post_descriptor_from_bytes(b: &[u8]) -> Result<PostDescriptor, CommandError> {
    if b.len() < POST_DESCRIPTOR_SIZE {
        return Err(CommandError::PostDescriptorDecodeError);
    }
    let mut _payload: Vec<u8> = vec![];
    _payload.push((b.len()-POST_DESCRIPTOR_SIZE) as u8);
    _payload.extend_from_slice(&b[POST_DESCRIPTOR_SIZE..]);
    return Ok(PostDescriptor {
            epoch: BigEndian::read_u64(&b[..8]),
            payload: _payload,
        });
}

pub struct PostDescriptorStatus {
    error_code: u8,
}

impl Command for PostDescriptorStatus {
    fn to_vec(&self) -> Vec<u8> {
        let mut out = vec![];
        out.push(POST_DESCRIPTOR_STATUS);
        let mut _len = [0u8; 4];
        BigEndian::write_u32(&mut _len, POST_DESCRIPTOR_STATUS_SIZE as u32);
        out.extend_from_slice(&_len);
        out.push(self.error_code);
        out
    }
}

fn post_descriptor_status_from_bytes(b: &[u8]) -> Result<PostDescriptorStatus, CommandError> {
    if b.len() != POST_DESCRIPTOR_STATUS_SIZE {
        return Err(CommandError::PostDescriptorStatusDecodeError);
    }
    return Ok(PostDescriptorStatus{
        error_code: b[0],
    });
}

pub struct Vote {
    epoch: u64,
    public_key: PublicKey,
    payload: Vec<u8>,
}

impl Command for Vote {
    fn to_vec(&self) -> Vec<u8> {
        let mut out = vec![];
        out.push(VOTE);
        let mut _len = [0u8; 4];
        BigEndian::write_u32(&mut _len, (VOTE_OVERHEAD+self.payload.len()) as u32);
        out.extend_from_slice(&_len);
        let mut _epoch = [0u8; 8];
        BigEndian::write_u64(&mut _epoch, self.epoch);
        out.extend_from_slice(&_epoch);
        out.extend_from_slice(&self.public_key.as_array());
        out.extend_from_slice(&self.payload);
        out
    }
}

fn vote_from_bytes(b: &[u8]) -> Result<Vote, CommandError> {
    if b.len() < VOTE_OVERHEAD {
        return Err(CommandError::VoteDecodeError);
    }
    let mut _public_key = PublicKey::default();
    _public_key.from_bytes(&b[8..40]).unwrap();
    return Ok(Vote{
        epoch: BigEndian::read_u64(&b[..8]),
        public_key: _public_key,
        payload: b[VOTE_OVERHEAD..].to_vec(),
    });
}

pub struct VoteStatus {
    error_code: u8,
}

impl Command for VoteStatus {
    fn to_vec(&self) -> Vec<u8> {
        let mut out = vec![];
        out.push(VOTE_STATUS);
        let mut _len = [0u8; 4];
        BigEndian::write_u32(&mut _len, VOTE_STATUS_SIZE as u32);
        out.extend_from_slice(&_len);
        out.push(self.error_code);
        out
    }
}

fn vote_status_from_bytes(b: &[u8]) -> Result<VoteStatus, CommandError> {
    if b.len() != VOTE_STATUS_SIZE {
        return Err(CommandError::VoteStatusDecodeError);
    }
    return Ok(VoteStatus{
        error_code: b[0],
    });
}

pub struct Disconnect {}

impl Command for Disconnect {
    fn to_vec(&self) -> Vec<u8> {
        let mut out = vec![0; CMD_OVERHEAD];
        out[0] = DISCONNECT;
        out
    }
}

pub struct SendPacket {
    sphinx_packet: Vec<u8>,
}

impl Command for SendPacket {
    fn to_vec(&self) -> Vec<u8> {
        let mut out = vec![];
        out.push(SEND_PACKET);
        let mut _len = [0u8; 4];
        BigEndian::write_u32(&mut _len, self.sphinx_packet.len() as u32);
        out.extend_from_slice(&_len);
        out.extend_from_slice(&self.sphinx_packet);
        out
    }
}

fn send_packet_from_bytes(b: &[u8]) -> Result<SendPacket, CommandError> {
    return Ok(SendPacket{
        sphinx_packet: b.to_vec(),
    });
}

pub struct RetrieveMessage {
    sequence: u32,
}

impl Command for RetrieveMessage {
    fn to_vec(&self) -> Vec<u8> {
        let mut out = vec![];
        out.push(RETRIEVE_MESSAGE);
        let mut _len = [0u8; 4];
        BigEndian::write_u32(&mut _len, RETRIEVE_MESSAGE_SIZE as u32);
        out.extend_from_slice(&_len);
        let mut _seq = [0u8; 4];
        BigEndian::write_u32(&mut _len, self.sequence);
        out.extend_from_slice(&_seq);
        out
    }
}

fn retrieve_message_from_bytes(b: &[u8]) -> Result<RetrieveMessage, CommandError> {
    if b.len() != RETRIEVE_MESSAGE_SIZE {
        return Err(CommandError::RetreiveMessageDecodeError);
    }
    return Ok(RetrieveMessage{
        sequence: BigEndian::read_u32(&b[..4]),
    });
}

pub struct MessageAck {
    queue_size_hint: u8,
    sequence: u32,
    id: [u8; SURB_ID_SIZE],
    payload: Vec<u8>,
}

impl Command for MessageAck {
    fn to_vec(&self) -> Vec<u8> {
        if self.payload.len() != PAYLOAD_TAG_SIZE + FORWARD_PAYLOAD_SIZE {
            panic!("invalid MessageAck payload when serializing");
        }
        let mut out = vec![];
        out.push(MESSAGE);
        let mut _len = [0u8; 4];
        BigEndian::write_u32(&mut _len, (MESSAGE_ACK_SIZE + self.payload.len()) as u32);
        out.extend_from_slice(&_len);
        out.push(MESSAGE_TYPE_ACK);
        out.push(self.queue_size_hint);
        let mut _seq = [0u8; 4];
        BigEndian::write_u32(&mut _seq, self.sequence);
        out.extend_from_slice(&_seq);
        out.extend_from_slice(&self.id);
        out.extend_from_slice(&self.payload);
        out
    }
}

pub struct Message {
    queue_size_hint: u8,
    sequence: u32,
    payload: Vec<u8>,
}

impl Command for Message {
    fn to_vec(&self) -> Vec<u8> {
        if self.payload.len() != USER_FORWARD_PAYLOAD_SIZE {
            panic!("invalid MessageAck payload when serializing");
        }
        let mut out = vec![];
        out.push(MESSAGE);
        let mut _len = [0u8; 4];
        BigEndian::write_u32(&mut _len, (MESSAGE_MSG_SIZE + self.payload.len()) as u32);
        out.extend_from_slice(&_len);
        out.push(MESSAGE_TYPE_MESSAGE);
        out.push(self.queue_size_hint);
        let mut _seq = [0u8; 4];
        BigEndian::write_u32(&mut _seq, self.sequence);
        out.extend_from_slice(&_seq);
        out.extend_from_slice(&self.payload);
        out
    }
}

pub struct MessageEmpty {
    sequence: u32,
}

impl Command for MessageEmpty {
    fn to_vec(&self) -> Vec<u8> {
        let mut out = vec![];
        out.push(MESSAGE);
        let mut _len = [0u8; 4];
        BigEndian::write_u32(&mut _len, MESSAGE_EMPTY_SIZE as u32);
        out.extend_from_slice(&_len);
        let mut _seq = [0u8; 4];
        BigEndian::write_u32(&mut _seq, self.sequence);
        out.extend_from_slice(&_seq);
        out
    }
}

fn message_from_bytes(b: &[u8]) -> Result<Box<Command>, CommandError> {
    if b.len() < MESSAGE_BASE_SIZE {
        return Err(CommandError::MessageDecodeError);
    }
    let _message_type = Some(b[0]);
    let _hint = b[1];
    let _seq = BigEndian::read_u32(&b[2..6]);
    let _msg = &b[MESSAGE_BASE_SIZE..];
    match _message_type {
        Some(MESSAGE_TYPE_ACK) => {
            if _msg.len() != SURB_ID_SIZE + PAYLOAD_TAG_SIZE + FORWARD_PAYLOAD_SIZE {
                return Err(CommandError::MessageDecodeError);
            }
            let mut _id = [0u8; SURB_ID_SIZE];
            _id.clone_from_slice(&_msg[..SURB_ID_SIZE]);
            let r = MessageAck {
                queue_size_hint: _hint,
                sequence: _seq,
                id: _id,
                payload: _msg[SURB_ID_SIZE..].to_vec(),
            };
            return Ok(Box::new(r));
        },
        Some(MESSAGE_TYPE_MESSAGE) => {
            if _msg.len() != MESSAGE_MSG_PADDING_SIZE + USER_FORWARD_PAYLOAD_SIZE {
                return Err(CommandError::MessageDecodeError);
            }
            return Err(CommandError::InvalidMessageType); // XXX
        },
        Some(MESSAGE_TYPE_EMPTY) => {
            return Err(CommandError::InvalidMessageType); // XXX
        },
        Some(_) => return Err(CommandError::InvalidMessageType),
        None => return Err(CommandError::InvalidMessageType),
    }
}
