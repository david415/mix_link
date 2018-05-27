// constants.rs - constants for noise based wire protocol
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


pub const NOISE_PARAMS: &'static str = "Noise_XX_25519_ChaChaPoly_BLAKE2b";
pub const PROLOGUE: [u8;1] = [0u8;1];
pub const PROLOGUE_SIZE: usize = 1;
pub const NOISE_MESSAGE_MAX_SIZE: usize = 65535;
pub const KEY_SIZE: usize = 32;
pub const MAC_SIZE: usize = 16;
pub const MAX_ADDITIONAL_DATA_SIZE: usize = 255;
pub const AUTH_MESSAGE_SIZE: usize = 1 + 4 + MAX_ADDITIONAL_DATA_SIZE;
pub const NOISE_HANDSHAKE_MESSAGE1_SIZE: usize = PROLOGUE_SIZE + KEY_SIZE;
pub const NOISE_HANDSHAKE_MESSAGE2_SIZE: usize = 101;
pub const NOISE_HANDSHAKE_MESSAGE3_SIZE: usize = 64;
pub const NOISE_MESSAGE_HEADER_SIZE: usize = MAC_SIZE + 4;
