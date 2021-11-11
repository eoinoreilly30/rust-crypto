struct Transaction {
    to: str,
    from: str,
    amount: f64
}

struct Block {
    previous_hash: str,
    transaction: Transaction
}

struct Wallet {
    public_key: str,
    private_key: str
}

fn main() {
    println!("Hello, world!");
}
