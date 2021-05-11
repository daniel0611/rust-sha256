use daniel0611_sha256::Sha256;
use std::{env, process};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("Missing argument.");
        process::exit(1);
    }

    let input = &args[1];
    let mut sha = Sha256::new();
    sha.update_string(input);
    let hash = sha.finish_hex();
    println!("{}", hash);
}
