// commands.rs - noise based wire protocol commands
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

// CONSENSUS_OK signifies that the GetConsensus request has completed
// successfully.
pub const CONSENSUS_OK: u8 = 0;

// CONSENSUS_NOT_FOUND signifies that the document document corresponding
// to the epoch in the GetConsensus was not found, but retrying later
// may be successful.
pub const CONSENSUS_NOT_FOUND: u8 = 1;

// CONSENSUS_GONE signifies that the document corresponding to the epoch
// in the GetConsensus was not found, and that retrying later will
// not be successful.
pub const CONSENSUS_GONE: u8 = 2;

// DESCRIPTOR_OK signifies that the PostDescriptor request has completed
// succcessfully.
pub const DESCRIPTOR_OK: u8 = 0;

// DESCRIPTOR_INVALID signifies that the PostDescriptor request has failed
// due to an unspecified error.
pub const DESCRIPTOR_INVALID: u8 = 1;

// DESCRIPTOR_CONFLICT signifies that the PostDescriptor request has
// failed due to the uploaded descriptor conflicting with a previously
// uploaded descriptor.
pub const DESCRIPTOR_CONFLICT: u8 = 2;

// DESCRIPTOR_FORBIDDEN signifies that the PostDescriptor request has
// failed due to an authentication error.
pub const DESCRIPTOR_FORBIDDEN: u8 = 3;

// VOTE_OK signifies that the vote was accepted by the peer.
pub const VOTE_OK: u8 = 0;

// VOTE_TOO_LATE signifies that the vote was too late.
pub const VOTE_TOO_LATE: u8 = 1;

// VOTE_TOO_EARLY signifies that the vote was too late.
pub const VOTE_TOO_EARLY: u8 = 2;

// VOTE_NOT_AUTHORIZED signifies that the voting entity's key is not white-listed.
pub const VOTE_NOT_AUTHORIZED: u8 = 3;

// VOTE_NOT_SIGNED signifies that the vote payload failed signature verification.
pub const VOTE_NOT_SIGNED: u8 = 4;

// VOTE_MALFORMED signifies that the vote payload was invalid.
pub const VOTE_MALFORMED: u8 = 5;

// VOTE_ALREADY_RECEIVED signifies that the vote from that peer was already received.
pub const VOTE_ALREADY_RECEIVED: u8 = 6;



#[derive(Clone)]
#[derive(PartialEq)]
#[derive(Debug)]
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
            return Err(CommandError::TooSmallError);
        }
        let cmd_id = b[0];
        if b[1] != 0 {
            return Err(CommandError::InvalidReservedByte);
        }
        let cmd_len = BigEndian::read_u32(&b[2..6]);
        let _cmd = &b[CMD_OVERHEAD..];
        if _cmd.len() < cmd_len as usize {
            let _padding = _cmd[cmd_len as usize..].to_vec();
            let _zeros = vec![0u8; cmd_len as usize];
            if _zeros.ct_eq(&_padding[..]).unwrap_u8() == 0 {
                return Err(CommandError::MessageDecodeError);
            }
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

        match cmd_id {
            SEND_PACKET => Ok(send_packet_from_bytes(_cmd).unwrap()),
            RETRIEVE_MESSAGE => Ok(retrieve_message_from_bytes(_cmd).unwrap()),
            MESSAGE => Ok(message_from_bytes(_cmd).unwrap()),
            GET_CONSENSUS => Ok(get_consensus_from_bytes(_cmd).unwrap()),
            CONSENSUS => Ok(consensus_from_bytes(_cmd).unwrap()),
            POST_DESCRIPTOR => Ok(post_descriptor_from_bytes(_cmd).unwrap()),
            POST_DESCRIPTOR_STATUS => Ok(post_descriptor_status_from_bytes(_cmd).unwrap()),
            VOTE => Ok(vote_from_bytes(_cmd).unwrap()),
            VOTE_STATUS => Ok(vote_status_from_bytes(_cmd).unwrap()),
            _ => Err(CommandError::MessageDecodeError),
        }
    }

    pub fn to_vec(&self) -> Vec<u8> {
        match self {
            Command::NoOp{} => {
                let mut out = vec![0; CMD_OVERHEAD];
                out[0] = NO_OP;
                out
            },
            Command::GetConsensus{
                epoch
            } => {
                let mut out = vec![0; CMD_OVERHEAD+GET_CONSENSUS_SIZE];
                out[0] = GET_CONSENSUS;
                BigEndian::write_u32(&mut out[2..6], GET_CONSENSUS_SIZE as u32);
                BigEndian::write_u64(&mut out[6..14], *epoch);
                out
            },
            Command::Consensus{
                error_code, payload
            } => {
                let consensus_size: usize = CONSENSUS_BASE_SIZE + payload.len();
                let mut out = vec![0u8; CMD_OVERHEAD + CONSENSUS_BASE_SIZE + payload.len()];
                out[0] = CONSENSUS;
                BigEndian::write_u32(&mut out[2..6], consensus_size as u32);
                out[6] = *error_code;
                out[CMD_OVERHEAD + CONSENSUS_BASE_SIZE..].copy_from_slice(payload);
                out
            },
            Command::PostDescriptor{
                epoch, payload
            } => {
                let mut out = vec![0u8; CMD_OVERHEAD + POST_DESCRIPTOR_SIZE + payload.len()];
                out[0] = POST_DESCRIPTOR;
                BigEndian::write_u32(&mut out[2..6], (POST_DESCRIPTOR_SIZE + payload.len()) as u32);
                BigEndian::write_u64(&mut out[6..14], *epoch);
                out[14..].copy_from_slice(payload);
                out
            },
            Command::PostDescriptorStatus{
                error_code
            } => {
                let mut out = vec![0u8; CMD_OVERHEAD + POST_DESCRIPTOR_STATUS_SIZE];
                out[0] = POST_DESCRIPTOR_STATUS;
                BigEndian::write_u32(&mut out[2..6], POST_DESCRIPTOR_STATUS_SIZE as u32);
                out[6] = *error_code;
                out
            },
            Command::Vote{
                epoch, public_key, payload
            } => {
                let mut out = vec![0u8; CMD_OVERHEAD + VOTE_OVERHEAD + payload.len()];
                out[0] = VOTE;
                BigEndian::write_u32(&mut out[2..6], (VOTE_OVERHEAD+payload.len()) as u32);
                BigEndian::write_u64(&mut out[6..14], *epoch);
                out[14..14+KEY_SIZE].copy_from_slice(&public_key.as_array());
                out[14+KEY_SIZE..].copy_from_slice(&payload);
                out
            },
            Command::VoteStatus{
                error_code
            } => {
                let mut out = vec![0u8; CMD_OVERHEAD + VOTE_STATUS_SIZE];
                out[0] = VOTE_STATUS;
                BigEndian::write_u32(&mut out[2..6], VOTE_STATUS_SIZE as u32);
                out[6] = *error_code;
                out
            },
            Command::Disconnect{} => {
                let mut out = vec![0; CMD_OVERHEAD];
                out[0] = DISCONNECT;
                out
            },
            Command::SendPacket{
                sphinx_packet
            } => {
                let mut out = vec![0; CMD_OVERHEAD + sphinx_packet.len()];
                out[0] = SEND_PACKET;
                BigEndian::write_u32(&mut out[2..6], sphinx_packet.len() as u32);
                out[6..].copy_from_slice(sphinx_packet);
                out
            },
            Command::RetrieveMessage{
                sequence
            } => {
                let mut out = vec![0; CMD_OVERHEAD + RETRIEVE_MESSAGE_SIZE];
                out[0] = RETRIEVE_MESSAGE;
                BigEndian::write_u32(&mut out[2..6], RETRIEVE_MESSAGE_SIZE as u32);
                BigEndian::write_u32(&mut out[6..], *sequence);
                out
            },
            Command::MessageAck{
                queue_size_hint, sequence, id, payload
            } => {
                if payload.len() != PAYLOAD_TAG_SIZE + FORWARD_PAYLOAD_SIZE {
                    panic!("invalid MessageAck payload when serializing");
                }
                let mut out = vec![0; CMD_OVERHEAD + MESSAGE_ACK_SIZE + payload.len()];
                out[0] = MESSAGE;
                BigEndian::write_u32(&mut out[2..6], (MESSAGE_ACK_SIZE + payload.len()) as u32);
                out[6] = MESSAGE_TYPE_ACK;
                out[7] = *queue_size_hint;
                BigEndian::write_u32(&mut out[8..12], *sequence);
                out[12..12+SURB_ID_SIZE].copy_from_slice(id);
                out[12+SURB_ID_SIZE..].copy_from_slice(payload);
                out
            },
            Command::MessageMessage{
                queue_size_hint, sequence, payload
            } => {
                if payload.len() != USER_FORWARD_PAYLOAD_SIZE {
                    panic!("invalid MessageAck payload when serializing");
                }
                let mut out = vec![0; CMD_OVERHEAD + MESSAGE_MSG_SIZE + payload.len()];
                out[0] = MESSAGE;
                BigEndian::write_u32(&mut out[2..6], (MESSAGE_MSG_SIZE + payload.len()) as u32);
                out[6] = MESSAGE_TYPE_MESSAGE;
                out[7] = *queue_size_hint;
                BigEndian::write_u32(&mut out[8..12], *sequence);
                out[12..12+payload.len()].copy_from_slice(payload);
                out
            },
            Command::MessageEmpty {
                sequence
            } => {
                let mut out = vec![0; CMD_OVERHEAD + MESSAGE_EMPTY_SIZE];
                out[0] = MESSAGE;
                BigEndian::write_u32(&mut out[2..6], MESSAGE_EMPTY_SIZE as u32);
                out[6] = MESSAGE_TYPE_EMPTY;
                BigEndian::write_u32(&mut out[8..12], *sequence);
                out
            },
        }
    }
}

fn get_consensus_from_bytes(b: &[u8]) -> Result<Command, CommandError> {
    if b.len() != GET_CONSENSUS_SIZE {
        println!("wtfff {} != {}", b.len(), GET_CONSENSUS_SIZE);
        return Err(CommandError::GetConsensusDecodeError);
    }
    Ok(Command::GetConsensus{
        epoch: BigEndian::read_u64(&b[..8]),
    })
}

fn consensus_from_bytes(b: &[u8]) -> Result<Command, CommandError> {
    if b.len() < CONSENSUS_BASE_SIZE {
        return Err(CommandError::ConsensusDecodeError);
    }
    let _payload_len = (b.len() - CONSENSUS_BASE_SIZE) as u8;
    let mut _payload: Vec<u8> = vec![];
    if _payload_len > 0 {
        _payload.extend_from_slice(&b[CONSENSUS_BASE_SIZE..]);
    }
    Ok(Command::Consensus {
        error_code: b[0],
        payload: _payload,
    })
}

fn post_descriptor_from_bytes(b: &[u8]) -> Result<Command, CommandError> {
    if b.len() < POST_DESCRIPTOR_SIZE {
        return Err(CommandError::PostDescriptorDecodeError);
    }
    let mut _payload: Vec<u8> = vec![];
    _payload.extend_from_slice(&b[POST_DESCRIPTOR_SIZE..]);
    Ok(Command::PostDescriptor {
        epoch: BigEndian::read_u64(&b[..POST_DESCRIPTOR_SIZE]),
        payload: _payload,
    })
}

fn post_descriptor_status_from_bytes(b: &[u8]) -> Result<Command, CommandError> {
    if b.len() != POST_DESCRIPTOR_STATUS_SIZE {
        return Err(CommandError::PostDescriptorStatusDecodeError);
    }
    Ok(Command::PostDescriptorStatus{
        error_code: b[0],
    })
}

fn vote_from_bytes(b: &[u8]) -> Result<Command, CommandError> {
    if b.len() < VOTE_OVERHEAD {
        return Err(CommandError::VoteDecodeError);
    }
    let mut _public_key = PublicKey::default();
    _public_key.from_bytes(&b[8..40]).unwrap();
    Ok(Command::Vote{
        epoch: BigEndian::read_u64(&b[..8]),
        public_key: _public_key,
        payload: b[VOTE_OVERHEAD..].to_vec(),
    })
}

fn vote_status_from_bytes(b: &[u8]) -> Result<Command, CommandError> {
    if b.len() != VOTE_STATUS_SIZE {
        return Err(CommandError::VoteStatusDecodeError);
    }
    Ok(Command::VoteStatus{
        error_code: b[0],
    })
}

fn send_packet_from_bytes(b: &[u8]) -> Result<Command, CommandError> {
    Ok(Command::SendPacket{
        sphinx_packet: b.to_vec(),
    })
}

fn retrieve_message_from_bytes(b: &[u8]) -> Result<Command, CommandError> {
    if b.len() != RETRIEVE_MESSAGE_SIZE {
        return Err(CommandError::RetreiveMessageDecodeError);
    }
    Ok(Command::RetrieveMessage{
        sequence: BigEndian::read_u32(&b[..4]),
    })
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
            Ok(r)
        },
        MESSAGE_TYPE_MESSAGE => {
            if _msg.len() != MESSAGE_MSG_PADDING_SIZE + USER_FORWARD_PAYLOAD_SIZE {
                return Err(CommandError::MessageDecodeError);
            }

            let zeros = [0u8; USER_FORWARD_PAYLOAD_SIZE];
            if zeros.ct_eq(&_msg[USER_FORWARD_PAYLOAD_SIZE..]).unwrap_u8() != 0 {
                return Err(CommandError::MessageDecodeError);
            }
            let _msg = &_msg[..USER_FORWARD_PAYLOAD_SIZE];
            let _message = Command::MessageMessage {
                queue_size_hint: _hint,
                sequence: _seq,
                payload: _msg.to_vec(),
            };
            Ok(_message)
        },
        MESSAGE_TYPE_EMPTY => {
            if _msg.len() != MESSAGE_EMPTY_SIZE - MESSAGE_BASE_SIZE {
                return Err(CommandError::MessageDecodeError);
            }
            let zeros = [0u8; MESSAGE_EMPTY_SIZE - MESSAGE_BASE_SIZE];
            if zeros.ct_eq(&_msg[MESSAGE_EMPTY_SIZE - MESSAGE_BASE_SIZE..]).unwrap_u8() != 0 {
                return Err(CommandError::MessageDecodeError);
            }
            Ok(Command::MessageEmpty{
                sequence: _seq,
            })
        },
        _ => Err(CommandError::InvalidMessageType),
    }
}

#[cfg(test)]
mod tests {
    extern crate rand;
    //extern crate rustc_serialize;
    extern crate ecdh_wrapper;

    //use self::rustc_serialize::hex::ToHex;
    use self::rand::os::OsRng;
    use ecdh_wrapper::PrivateKey;

    use super::*;

    #[test]
    fn commands_test() {
        let mut r = OsRng::new().expect("failure to create an OS RNG");

        // test no op
        let no_op = Command::NoOp{};
        let no_op_bytes = no_op.clone().to_vec();
        let no_op2 = Command::from_bytes(&no_op_bytes).unwrap();
        assert_eq!(no_op, no_op2);
        let no_op2_bytes = no_op2.to_vec();
        assert_eq!(no_op_bytes, no_op2_bytes);

        // test get consensus
        let get_consensus = Command::GetConsensus{
            epoch: 123,
        };
        let get_consensus_bytes = get_consensus.clone().to_vec();
        let get_consensus2 = Command::from_bytes(&get_consensus_bytes).unwrap();
        assert_eq!(get_consensus, get_consensus2);
        let get_consensus2_bytes = get_consensus2.to_vec();
        assert_eq!(get_consensus_bytes, get_consensus2_bytes);

        // test consensus
        let consensus = Command::Consensus{
            error_code: CONSENSUS_OK,
            payload: String::from("TANSTAFL: There's ain't no such thing as a free lunch.").into_bytes(),
        };
        let consensus_bytes = consensus.clone().to_vec();
        let consensus2 = Command::from_bytes(&consensus_bytes).unwrap();
        assert_eq!(consensus, consensus2);
        let consensus2_bytes = consensus2.to_vec();
        assert_eq!(consensus_bytes, consensus2_bytes);

        // test post descriptor
        let post_descriptor = Command::PostDescriptor {
            epoch: 123,
            payload: String::from("This is my descriptor.").into_bytes(),
        };
        let post_descriptor_bytes = post_descriptor.clone().to_vec();
        let post_descriptor2 = Command::from_bytes(&post_descriptor_bytes).unwrap();
        assert_eq!(post_descriptor, post_descriptor2);
        let post_descriptor2_bytes = post_descriptor2.to_vec();
        assert_eq!(post_descriptor_bytes, post_descriptor2_bytes);

        // test post descriptor status
        let post_descriptor_status = Command::PostDescriptorStatus {
            error_code: DESCRIPTOR_OK,
        };
        let post_descriptor_status_bytes = post_descriptor_status.clone().to_vec();
        let post_descriptor_status2 = Command::from_bytes(&post_descriptor_status_bytes).unwrap();
        assert_eq!(post_descriptor_status, post_descriptor_status2);
        let post_descriptor_status2_bytes = post_descriptor_status2.to_vec();
        assert_eq!(post_descriptor_status_bytes, post_descriptor_status2_bytes);

        // test vote
        let private_key = PrivateKey::generate(&mut r);
        let public_key = private_key.public_key();
        let vote = Command::Vote{
            epoch: 123,
            public_key,
            payload: vec![1,2,3,4],
        };
        let vote_bytes = vote.clone().to_vec();
        let vote2 = Command::from_bytes(&vote_bytes).unwrap();
        assert_eq!(vote, vote2);
        let vote2_bytes = vote2.to_vec();
        assert_eq!(vote_bytes, vote2_bytes);

        // test vote_status
        let vote_status = Command::VoteStatus{
            error_code: VOTE_OK,
        };
        let vote_status_bytes = vote_status.clone().to_vec();
        let vote_status2 = Command::from_bytes(&vote_status_bytes).unwrap();
        assert_eq!(vote_status, vote_status2);
        let vote_status2_bytes = vote_status2.to_vec();
        assert_eq!(vote_status_bytes, vote_status2_bytes);

        // test disconnect
        let disconnect = Command::Disconnect{};
        let disconnect_bytes = disconnect.clone().to_vec();
        let disconnect2 = Command::from_bytes(&disconnect_bytes).unwrap();
        assert_eq!(disconnect, disconnect2);
        let disconnect2_bytes = disconnect2.to_vec();
        assert_eq!(disconnect_bytes, disconnect2_bytes);

        // test send packet
        let send_packet = Command::SendPacket{
            sphinx_packet: vec![1,2,3,4,5,6,7],
        };
        let send_packet_bytes = send_packet.clone().to_vec();
        let send_packet2 = Command::from_bytes(&send_packet_bytes).unwrap();
        assert_eq!(send_packet, send_packet2);
        let send_packet2_bytes = send_packet2.to_vec();
        assert_eq!(send_packet_bytes, send_packet2_bytes);

        // test retrieve message
        let retrieve_message = Command::RetrieveMessage{
            sequence: 123,
        };
        let retrieve_message_bytes = retrieve_message.clone().to_vec();
        let retrieve_message2 = Command::from_bytes(&retrieve_message_bytes).unwrap();
        assert_eq!(retrieve_message, retrieve_message2);
        let retrieve_message2_bytes = retrieve_message2.to_vec();
        assert_eq!(retrieve_message_bytes, retrieve_message2_bytes);

        // test message ack
        let id = [0u8; SURB_ID_SIZE];
        let message_ack = Command::MessageAck{
            queue_size_hint: 0,
            sequence: 123,
            id,
            payload: vec![0u8; PAYLOAD_TAG_SIZE + FORWARD_PAYLOAD_SIZE],
        };
        let message_ack_bytes = message_ack.clone().to_vec();
        let message_ack2 = Command::from_bytes(&message_ack_bytes).unwrap();
        assert_eq!(message_ack, message_ack2);
        let message_ack2_bytes = message_ack2.to_vec();
        assert_eq!(message_ack_bytes, message_ack2_bytes);

        // test message message
        let message_message = Command::MessageMessage{
            queue_size_hint: 0,
            sequence: 123,
            payload: vec![0u8; USER_FORWARD_PAYLOAD_SIZE],
        };
        let message_message_bytes = message_message.clone().to_vec();
        let message_message2 = Command::from_bytes(&message_message_bytes).unwrap();
        assert_eq!(message_message, message_message2);
        let message_message2_bytes = message_message2.to_vec();
        assert_eq!(message_message_bytes, message_message2_bytes);

        // test message empty
        let message_empty = Command::MessageEmpty{
            sequence: 123,
        };
        let message_empty_bytes = message_empty.clone().to_vec();
        let message_empty2 = Command::from_bytes(&message_empty_bytes).unwrap();
        assert_eq!(message_empty, message_empty2);
        let message_empty2_bytes = message_empty2.to_vec();
        assert_eq!(message_empty_bytes, message_empty2_bytes);
    }
}
