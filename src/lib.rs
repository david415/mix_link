// lib.rs - noise based wire protocol for building mix networks
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

extern crate snow;
extern crate ecdh_wrapper;
extern crate byteorder;
extern crate subtle;
extern crate sphinxcrypto;

pub mod errors;
pub mod constants;
pub mod commands;
pub mod messages;



#[cfg(test)]
mod tests {

    //extern crate rustc_serialize;
    extern crate ecdh_wrapper;
    extern crate rand;

    use self::rand::os::OsRng;

    use snow::NoiseBuilder;
    use snow::params::NoiseParams;

    //use self::rustc_serialize::hex::ToHex;
    use self::ecdh_wrapper::PrivateKey;


    #[test]
    fn noise_test() {
        let noise_params: NoiseParams = "Noise_XX_25519_ChaChaPoly_BLAKE2b".parse().unwrap();
        let prologue = [0u8;1];
        let mut r = OsRng::new().expect("failure to create an OS RNG");

        // server
        let server_keypair = PrivateKey::generate(&mut r).unwrap();
        let server_builder: NoiseBuilder = NoiseBuilder::new(noise_params.clone());
        let mut server_session = server_builder
            .local_private_key(&server_keypair.to_vec())
            .prologue(&prologue)
            .build_responder().unwrap();
        let mut server_in = [0u8; 65535];
        let mut server_out = [0u8; 65535];

        // client
        let client_keypair = PrivateKey::generate(&mut r).unwrap();
        let client_builder: NoiseBuilder = NoiseBuilder::new(noise_params.clone());
        let mut client_session = client_builder
            .local_private_key(&client_keypair.to_vec())
            .remote_public_key(&server_keypair.public_key().to_vec())
            .prologue(&prologue)
            .build_initiator().unwrap();
        let mut client_out = [0u8; 65535];
        let mut client_in = [0u8; 65535];

        // handshake
        let mut _client_len = client_session.write_message(&[0u8; 1], &mut client_out).unwrap();
        let mut _server_len = server_session.read_message(&client_out[.._client_len], &mut server_in).unwrap();
        println!("c -> s {}", _client_len);

        _server_len = server_session.write_message(&[0u8; 1], &mut server_out).unwrap();
        _client_len = client_session.read_message(&server_out[.._server_len], &mut client_in).unwrap();
        println!("s -> c {}", _server_len);

        _client_len = client_session.write_message(&[], &mut client_out).unwrap();
        server_session.read_message(&client_out[.._client_len], &mut server_in).unwrap();
        println!("c -> s {}", _client_len);

        // data transfer
        client_session = client_session.into_transport_mode().unwrap();
        server_session = server_session.into_transport_mode().unwrap();

        // server talks to client
        let server_banner = b"yo";
        _server_len = server_session.write_message(server_banner, &mut server_out).unwrap();
        client_session.read_message(&server_out[.._server_len], &mut client_in).unwrap();
        assert_eq!(&client_in[..server_banner.len()], server_banner);

        // client talks to server
        let client_response = b"ho";
        _client_len = client_session.write_message(client_response, &mut client_out).unwrap();
        server_session.read_message(&client_out[.._client_len], &mut server_in).unwrap();
        assert_eq!(client_response, &server_in[..client_response.len()]);
    }
}
