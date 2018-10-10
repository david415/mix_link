// lib.rs - noise based wire protocol for building mix networks
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
extern crate ecdh_wrapper;
extern crate byteorder;
extern crate subtle;
extern crate sphinxcrypto;

pub mod errors;
pub mod constants;
pub mod commands;
pub mod messages;
pub mod sync;


#[cfg(test)]
mod tests {

    //extern crate rustc_serialize;
    extern crate ecdh_wrapper;
    extern crate rand;
    extern crate snow;

    use self::rand::os::OsRng;

    use snow::Builder;
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
        let server_builder: Builder = Builder::new(noise_params.clone());
        let mut server_session = server_builder
            .local_private_key(&server_keypair.to_vec())
            .prologue(&prologue)
            .build_responder().unwrap();
        let mut server_in = [0u8; 65535];
        let mut server_out = [0u8; 65535];

        // client
        let client_keypair = PrivateKey::generate(&mut r).unwrap();
        let client_builder: Builder = Builder::new(noise_params.clone());
        let mut client_session = client_builder
            .local_private_key(&client_keypair.to_vec())
            .remote_public_key(&server_keypair.public_key().to_vec())
            .prologue(&prologue)
            .build_initiator().unwrap();
        let mut client_out = [0u8; 65535];
        let mut client_in = [0u8; 65535];

        // handshake
        let mut _client_len = client_session.write_message(&[0u8; 0], &mut client_out).unwrap();
        let mut _server_len = server_session.read_message(&client_out[.._client_len], &mut server_in).unwrap();
        println!("c -> s {}", _client_len);

        _server_len = server_session.write_message(&[0u8; 0], &mut server_out).unwrap();
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
