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

use std::any::Any;
use byteorder::{ByteOrder, BigEndian};
use subtle::ConstantTimeEq;
use ecdh_wrapper::{KEY_SIZE, PublicKey};

use sphinxcrypto::constants::{FORWARD_PAYLOAD_SIZE,
                              PAYLOAD_TAG_SIZE,
                              SURB_ID_SIZE,
                              SPHINX_PLAINTEXT_HEADER_SIZE,
                              SURB_SIZE,
                              USER_FORWARD_PAYLOAD_SIZE};

use super::errors::CommandError;

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


#[derive(Clone)]
pub enum Command {
    NoOp {},
    GetConsensus {
        epoch: u64,
    },
    Consensus {
        error_code: u8,
        payload: Vec<u8>,
    },
    PostDescriptor {
        epoch: u64,
        payload: Vec<u8>,
    },
    PostDescriptorStatus {
        error_code: u8,
    },
    Vote {
        epoch: u64,
        public_key: PublicKey,
        payload: Vec<u8>,
    },
    VoteStatus {
        error_code: u8,
    },
    Disconnect {},
    SendPacket {
        sphinx_packet: Vec<u8>,
    },
    RetrieveMessage {
        sequence: u32,
    },
    MessageAck {
        queue_size_hint: u8,
        sequence: u32,
        id: [u8; SURB_ID_SIZE],
        payload: Vec<u8>,
    },
    MessageMessage {
        queue_size_hint: u8,
        sequence: u32,
        payload: Vec<u8>,
    },
    MessageEmpty {
        sequence: u32,
    },
}

impl Command {
    pub fn from_bytes(b: &[u8]) -> Result<Command, CommandError> {
        if b.len() < CMD_OVERHEAD {
            return Err(CommandError::InvalidMessageType);
        }
        let cmd_id = b[0];
        if b[1] != 0 {
            return Err(CommandError::InvalidMessageType);
        }
        let cmd_len = BigEndian::read_u32(&b[2..6]);
        let _cmd = &b[CMD_OVERHEAD..];
        if _cmd.len() < cmd_len as usize {
            return Err(CommandError::InvalidMessageType);
        }
        let _padding = &_cmd[cmd_len as usize..];
        let _zeros = vec![0u8; cmd_len as usize];
        if _zeros.ct_eq(&_padding).unwrap_u8() == 0 {
            return Err(CommandError::MessageDecodeError);
        }
        // handle commands with no payload
        if cmd_len == 0 {
            match cmd_id {
                NO_OP => return Ok(Command::NoOp{}),
                DISCONNECT => return Ok(Command::Disconnect{}),
                SEND_PACKET => return Err(CommandError::MessageDecodeError),
                POST_DESCRIPTOR => return Err(CommandError::MessageDecodeError),
                _ => return Err(CommandError::MessageDecodeError),
            }
        }
        let _cmd = &_cmd[CMD_OVERHEAD..];
        if _cmd.len() < cmd_len as usize {
            return Err(CommandError::MessageDecodeError);
        }
        match cmd_id {
            SEND_PACKET => return Ok(send_packet_from_bytes(_cmd).unwrap()),
            RETRIEVE_MESSAGE => return Ok(retrieve_message_from_bytes(_cmd).unwrap()),
            MESSAGE => return Ok(message_from_bytes(_cmd).unwrap()),
            GET_CONSENSUS => return Ok(get_consensus_from_bytes(_cmd).unwrap()),
            POST_DESCRIPTOR => return Ok(post_descriptor_from_bytes(_cmd).unwrap()),
            VOTE => return Ok(vote_from_bytes(_cmd).unwrap()),
            VOTE_STATUS => return Ok(vote_status_from_bytes(_cmd).unwrap()),
            _ => return Err(CommandError::MessageDecodeError),
        }
        return Err(CommandError::InvalidMessageType)
    }

    pub fn to_vec(self) -> Vec<u8> {
        match self {
            Command::NoOp{} => {
                let mut out = vec![0; CMD_OVERHEAD];
                out[0] = NO_OP;
                return out;
            },
            Command::GetConsensus{
                epoch
            } => {
                let mut out = vec![0; CMD_OVERHEAD+GET_CONSENSUS_SIZE];
                out[0] = GET_CONSENSUS;
                BigEndian::write_u32(&mut out[2..6], GET_CONSENSUS_SIZE as u32);
                BigEndian::write_u64(&mut out[6..14], epoch);
                return out;
            },
            Command::Consensus{
                error_code, payload
            } => {
                let consensus_size: usize = CONSENSUS_BASE_SIZE + payload.len();
                let mut out = vec![];
                out.push(CONSENSUS);
                let mut _len_raw = [0u8; 4];
                BigEndian::write_u32(&mut _len_raw[2..6], consensus_size as u32);
                out.extend_from_slice(&_len_raw);
                out.push(error_code);
                out.extend_from_slice(&payload);
                return out;
            },
            Command::PostDescriptor{
                epoch, payload
            } => {
                let mut out = vec![];
                out.push(POST_DESCRIPTOR);
                let mut _desc_len = [0u8; 4];
                BigEndian::write_u32(&mut _desc_len, POST_DESCRIPTOR_SIZE as u32 + payload.len() as u32);
                out.extend_from_slice(&_desc_len);
                let mut _epoch = [0u8; 8];
                BigEndian::write_u64(&mut _epoch, epoch);
                out.extend_from_slice(&_epoch);
                out.extend_from_slice(&payload);
                return out;
            },
            Command::PostDescriptorStatus{
                error_code
            } => {
                let mut out = vec![];
                out.push(POST_DESCRIPTOR_STATUS);
                let mut _len = [0u8; 4];
                BigEndian::write_u32(&mut _len, POST_DESCRIPTOR_STATUS_SIZE as u32);
                out.extend_from_slice(&_len);
                out.push(error_code);
                return out;
            },
            Command::Vote{
                epoch, public_key, payload
            } => {
                let mut out = vec![];
                out.push(VOTE);
                let mut _len = [0u8; 4];
                BigEndian::write_u32(&mut _len, (VOTE_OVERHEAD+payload.len()) as u32);
                out.extend_from_slice(&_len);
                let mut _epoch = [0u8; 8];
                BigEndian::write_u64(&mut _epoch, epoch);
                out.extend_from_slice(&_epoch);
                out.extend_from_slice(&public_key.as_array());
                out.extend_from_slice(&payload);
                return out;
            },
            Command::VoteStatus{
                error_code
            } => {
                let mut out = vec![];
                out.push(VOTE_STATUS);
                let mut _len = [0u8; 4];
                BigEndian::write_u32(&mut _len, VOTE_STATUS_SIZE as u32);
                out.extend_from_slice(&_len);
                out.push(error_code);
                return out;
            },
            Command::Disconnect{} => {
                let mut out = vec![0; CMD_OVERHEAD];
                out[0] = DISCONNECT;
                return out;
            },
            Command::SendPacket{
                sphinx_packet
            } => {
                let mut out = vec![];
                out.push(SEND_PACKET);
                let mut _len = [0u8; 4];
                BigEndian::write_u32(&mut _len, sphinx_packet.len() as u32);
                out.extend_from_slice(&_len);
                out.extend_from_slice(&sphinx_packet);
                return out;
            },
            Command::RetrieveMessage{
                sequence
            } => {
                let mut out = vec![];
                out.push(RETRIEVE_MESSAGE);
                let mut _len = [0u8; 4];
                BigEndian::write_u32(&mut _len, RETRIEVE_MESSAGE_SIZE as u32);
                out.extend_from_slice(&_len);
                let mut _seq = [0u8; 4];
                BigEndian::write_u32(&mut _len, sequence);
                out.extend_from_slice(&_seq);
                return out;
            },
            Command::MessageAck{
                queue_size_hint, sequence, id, payload
            } => {
                if payload.len() != PAYLOAD_TAG_SIZE + FORWARD_PAYLOAD_SIZE {
                    panic!("invalid MessageAck payload when serializing");
                }
                let mut out = vec![];
                out.push(MESSAGE);
                let mut _len = [0u8; 4];
                BigEndian::write_u32(&mut _len, (MESSAGE_ACK_SIZE + payload.len()) as u32);
                out.extend_from_slice(&_len);
                out.push(MESSAGE_TYPE_ACK);
                out.push(queue_size_hint);
                let mut _seq = [0u8; 4];
                BigEndian::write_u32(&mut _seq, sequence);
                out.extend_from_slice(&_seq);
                out.extend_from_slice(&id);
                out.extend_from_slice(&payload);
                return out;
            },
            Command::MessageMessage{
                queue_size_hint, sequence, payload
            } => {
                if payload.len() != USER_FORWARD_PAYLOAD_SIZE {
                    panic!("invalid MessageAck payload when serializing");
                }
                let mut out = vec![];
                out.push(MESSAGE);
                let mut _len = [0u8; 4];
                BigEndian::write_u32(&mut _len, (MESSAGE_MSG_SIZE + payload.len()) as u32);
                out.extend_from_slice(&_len);
                out.push(MESSAGE_TYPE_MESSAGE);
                out.push(queue_size_hint);
                let mut _seq = [0u8; 4];
                BigEndian::write_u32(&mut _seq, sequence);
                out.extend_from_slice(&_seq);
                out.extend_from_slice(&payload);
                return out;
            },
            Command::MessageEmpty {
                sequence
            } => {
                let mut out = vec![];
                out.push(MESSAGE);
                let mut _len = [0u8; 4];
                BigEndian::write_u32(&mut _len, MESSAGE_EMPTY_SIZE as u32);
                out.extend_from_slice(&_len);
                let mut _seq = [0u8; 4];
                BigEndian::write_u32(&mut _seq, sequence);
                out.extend_from_slice(&_seq);
                return out;
            },
        }
    }
}

fn get_consensus_from_bytes(b: &[u8]) -> Result<Command, CommandError> {
    if b.len() != GET_CONSENSUS_SIZE {
        return Err(CommandError::GetConsensusDecodeError);
    }
    return Ok(Command::GetConsensus{
        epoch: BigEndian::read_u64(&b[..8]),
    });
}

fn consensus_from_bytes(b: &[u8]) -> Result<Command, CommandError> {
    if b.len() < CONSENSUS_BASE_SIZE {
        return Err(CommandError::ConsensusDecodeError);
    }
    let _payload_len = (b.len() - CONSENSUS_BASE_SIZE) as u8;
    let mut _payload: Vec<u8> = vec![];
    if _payload_len > 0 {
        _payload.push(_payload_len);
        _payload.extend_from_slice(&b[CONSENSUS_BASE_SIZE..]);
    }
    return Ok(Command::Consensus {
        error_code: b[0],
        payload: _payload,
    });
}

fn post_descriptor_from_bytes(b: &[u8]) -> Result<Command, CommandError> {
    if b.len() < POST_DESCRIPTOR_SIZE {
        return Err(CommandError::PostDescriptorDecodeError);
    }
    let mut _payload: Vec<u8> = vec![];
    _payload.push((b.len()-POST_DESCRIPTOR_SIZE) as u8);
    _payload.extend_from_slice(&b[POST_DESCRIPTOR_SIZE..]);
    return Ok(Command::PostDescriptor {
            epoch: BigEndian::read_u64(&b[..8]),
            payload: _payload,
        });
}

fn post_descriptor_status_from_bytes(b: &[u8]) -> Result<Command, CommandError> {
    if b.len() != POST_DESCRIPTOR_STATUS_SIZE {
        return Err(CommandError::PostDescriptorStatusDecodeError);
    }
    return Ok(Command::PostDescriptorStatus{
        error_code: b[0],
    });
}

fn vote_from_bytes(b: &[u8]) -> Result<Command, CommandError> {
    if b.len() < VOTE_OVERHEAD {
        return Err(CommandError::VoteDecodeError);
    }
    let mut _public_key = PublicKey::default();
    _public_key.from_bytes(&b[8..40]).unwrap();
    return Ok(Command::Vote{
        epoch: BigEndian::read_u64(&b[..8]),
        public_key: _public_key,
        payload: b[VOTE_OVERHEAD..].to_vec(),
    });
}

fn vote_status_from_bytes(b: &[u8]) -> Result<Command, CommandError> {
    if b.len() != VOTE_STATUS_SIZE {
        return Err(CommandError::VoteStatusDecodeError);
    }
    return Ok(Command::VoteStatus{
        error_code: b[0],
    });
}

fn send_packet_from_bytes(b: &[u8]) -> Result<Command, CommandError> {
    return Ok(Command::SendPacket{
        sphinx_packet: b.to_vec(),
    });
}

fn retrieve_message_from_bytes(b: &[u8]) -> Result<Command, CommandError> {
    if b.len() != RETRIEVE_MESSAGE_SIZE {
        return Err(CommandError::RetreiveMessageDecodeError);
    }
    return Ok(Command::RetrieveMessage{
        sequence: BigEndian::read_u32(&b[..4]),
    });
}

fn message_from_bytes(b: &[u8]) -> Result<Command, CommandError> {
    if b.len() < MESSAGE_BASE_SIZE {
        return Err(CommandError::MessageDecodeError);
    }
    let _message_type = b[0];
    let _hint = b[1];
    let _seq = BigEndian::read_u32(&b[2..6]);
    let _msg = &b[MESSAGE_BASE_SIZE..];
    match _message_type {
        MESSAGE_TYPE_ACK => {
            if _msg.len() != SURB_ID_SIZE + PAYLOAD_TAG_SIZE + FORWARD_PAYLOAD_SIZE {
                return Err(CommandError::MessageDecodeError);
            }
            let mut _id = [0u8; SURB_ID_SIZE];
            _id.clone_from_slice(&_msg[..SURB_ID_SIZE]);
            let r = Command::MessageAck {
                queue_size_hint: _hint,
                sequence: _seq,
                id: _id,
                payload: _msg[SURB_ID_SIZE..].to_vec(),
            };
            return Ok(r);
        },
        MESSAGE_TYPE_MESSAGE => {
            if _msg.len() != MESSAGE_MSG_PADDING_SIZE + USER_FORWARD_PAYLOAD_SIZE {
                return Err(CommandError::MessageDecodeError);
            }

            let zeros = [0u8; USER_FORWARD_PAYLOAD_SIZE];
            if zeros.ct_eq(&_msg[USER_FORWARD_PAYLOAD_SIZE..]).unwrap_u8() == 0 {
                return Err(CommandError::MessageDecodeError);
            }
            let _msg = &_msg[..USER_FORWARD_PAYLOAD_SIZE];
            let _message = Command::MessageMessage {
                queue_size_hint: _hint,
                sequence: _seq,
                payload: _msg.to_vec(),
            };
            return Ok(_message);
        },
        MESSAGE_TYPE_EMPTY => {
            if _msg.len() != MESSAGE_EMPTY_SIZE - MESSAGE_BASE_SIZE {
                return Err(CommandError::MessageDecodeError);
            }
            let zeros = [0u8; MESSAGE_EMPTY_SIZE - MESSAGE_BASE_SIZE];
            if zeros.ct_eq(&_msg[MESSAGE_EMPTY_SIZE - MESSAGE_BASE_SIZE..]).unwrap_u8() == 0 {
                return Err(CommandError::MessageDecodeError);
            }
            return Ok(Command::MessageEmpty{
                sequence: _seq,
            });
        },
        _ => return Err(CommandError::InvalidMessageType),
    }
}
