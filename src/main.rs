extern crate ripemd160;
extern crate secp256k1;

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

fn public_key_to_wallet_address(public_key: &PublicKey) -> String {
    let public_key_hash = ripemd160_hash(&sha256_hash(&public_key.to_string()));
    println!("{}", public_key_hash);
    let test_net = String::from("6f");
    let versioned_public_key_hash = test_net + &public_key_hash;
    println!("{}", versioned_public_key_hash);
    let checksum = &sha256_hash(&sha256_hash(&versioned_public_key_hash))[..8];
    println!("{}", checksum);
    let byte_address = versioned_public_key_hash + &checksum;
    println!("{}", byte_address);
    let base58_encoded = base58check::to_base58check(hex::decode(byte_address).unwrap());
    base58_encoded
}

fn main() {
    let (_, public_key) = gen_keypair();
    println!("{}", public_key_to_wallet_address(&public_key));
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::Message;

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
    fn gen_keypair_sign_message() {
        let message = Message::from_slice(&hex::decode(sha256_hash(&"Hello")).unwrap()).expect("Must be 32 bytes");
        let (secret_key, public_key) = gen_keypair();
        let secp = Secp256k1::new();
        let sig = secp.sign(&message, &secret_key);
        assert!(secp.verify(&message, &sig, &public_key).is_ok());
    }
}
