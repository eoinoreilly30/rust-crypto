extern crate num_bigint;
extern crate num_traits;
extern crate ripemd160;
extern crate secp256k1;

use std::ops::{Div, Rem};

use num_bigint::BigInt;
use num_traits::{Num, ToPrimitive, Zero};
use ripemd160::{Digest, Ripemd160};
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use secp256k1::rand::rngs::OsRng;

use sha2::Sha256;

fn sha256_hash(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

fn ripemd160_hash(data: &str) -> String {
    let mut hasher = Ripemd160::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

fn gen_keypair() -> (SecretKey, PublicKey) {
    let secp = Secp256k1::new();
    let mut rng = OsRng::new().expect("Error creating OsRng");
    secp.generate_keypair(&mut rng)
}

fn base58_encode(hex_string: &str) -> String {
    assert_eq!(hex_string.len(), 50);
    let alphabet = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut n: BigInt = BigInt::from_str_radix(&hex_string, 16).expect("Error parsing BigInt from hex");
    let mut byte_array: Vec<u8> = Vec::new();
    while n > Zero::zero() {
        const LIMIT: i32 = 58;
        let orig_n = n.clone();
        n = n.div(LIMIT);
        let i: usize = orig_n.rem(LIMIT).to_usize().expect("Error converting to usize");
        // println!("{:?}, {:?}", n, i);
        byte_array.push(alphabet[i]);
    }
    let num_leading_zeroes = hex_string.len() - hex_string.trim_start_matches("00").len();
    println!("leading zeroes {}", num_leading_zeroes);
    byte_array.reverse();
    let byte_array_as_string = std::str::from_utf8(&byte_array).expect("Error parsing byte array");
    let encoded = "1".repeat(num_leading_zeroes) + &byte_array_as_string;
    encoded
}

fn public_key_to_wallet_address(public_key: &PublicKey) -> String {
    let public_key_hash = ripemd160_hash(&sha256_hash(&public_key.to_string()));
    println!("pub key hash {}", public_key_hash);
    let test_net = String::from("6f");
    let versioned_public_key_hash = test_net + &public_key_hash;
    println!("versioned {}", versioned_public_key_hash);
    let checksum = &sha256_hash(&sha256_hash(&versioned_public_key_hash))[..8];
    println!("checksum {}", checksum);
    let hex_address = versioned_public_key_hash + &checksum;
    println!("hex address {}", hex_address);
    let base58check_encoded = base58_encode(&hex_address);
    base58check_encoded
}

fn main() {
    let (secret_key, public_key) = gen_keypair();
    println!("{:?}", (secret_key, public_key));
    println!("{}", public_key_to_wallet_address(&public_key));
}

#[cfg(test)]
mod tests {
    use secp256k1::Message;

    use super::*;

    #[test]
    fn sha256_hash_empty() {
        assert_eq!(sha256_hash(&""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    #[test]
    fn sha256_hash_hello() {
        assert_eq!(sha256_hash(&"Hello"), "185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969");
    }

    #[test]
    fn ripemd160_hash_empty() {
        assert_eq!(ripemd160_hash(&""), "9c1185a5c5e9fc54612808977ee8f548b2258d31");
    }

    #[test]
    fn ripemd160_hash_hello() {
        assert_eq!(ripemd160_hash(&"Hello"), "d44426aca8ae0a69cdbc4021c64fa5ad68ca32fe");
    }

    #[test]
    fn base58_encode_test() {
        assert_eq!(base58_encode(&"00010966776006953D5567439E5E39F86A0D273BEED61967F6"), "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM")
    }

    #[test]
    fn gen_keypair_sign_message() {
        let message = Message::from_slice(&hex::decode(sha256_hash(&"Hello")).unwrap()).expect("Must be 32 bytes");
        let (secret_key, public_key) = gen_keypair();
        let secp = Secp256k1::new();
        let sig = secp.sign(&message, &secret_key);
        assert!(secp.verify(&message, &sig, &public_key).is_ok());
    }
}
