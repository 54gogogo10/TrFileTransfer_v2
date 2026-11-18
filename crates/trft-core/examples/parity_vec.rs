use reed_solomon_erasure::galois_8::ReedSolomon;

fn main() {
    let k = 4usize;
    let len = 8usize;
    let r = 2usize;
    let enc = ReedSolomon::new(k, r).unwrap();
    let mut shards: Vec<Vec<u8>> = (0..k)
        .map(|i| (0..len).map(|b| (i * 37 + b * 11 + 5) as u8).collect())
        .collect();
    for _ in 0..r {
        shards.push(vec![0u8; len]);
    }
    enc.encode(&mut shards).unwrap();
    for (i, s) in shards.iter().enumerate() {
        print!("{}:", i);
        for b in s {
            print!("{:02x}", b);
        }
        println!();
    }
}
