use sha2::{Sha256, Digest};

// struct Transaction {
//     to: String,
//     from: String,
//     amount: f64,
// }
//
// struct Block {
//     previous_hash: String,
//     transaction: Transaction,
// }
//
// struct Wallet {
//     public_key: String,
//     private_key: String,
// }

fn sha256_hash(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

fn main() {
    println!("{}", sha256_hash(&"Hello"));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_hash_empty() {
        assert_eq!(sha256_hash(&""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    #[test]
    fn sha256_hash_hello() {
        assert_eq!(sha256_hash(&"Hello"), "185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969")
    }
}
