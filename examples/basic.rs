use daniel0611_sha256::Sha256;

fn main() {
    let mut sha = Sha256::new();
    let input = "Hello world!";
    sha.update_string(input);
    let hash_hex = sha.finish_hex();
    println!("The hash of \"{}\" is {}", input, hash_hex);
    assert_eq!(hash_hex, "c0535e4be2b79ffd93291305436bf889314e4a3faec05ecffcbb7df31ad9e51a");
}