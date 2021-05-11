#![allow(dead_code)]
#![feature(test)]

use std::convert::TryInto;

pub struct Sha256 {
    h: [u32; 8],
}

const H_INIT: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const K_CONST: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

// TODO: will I hate little/big endianness after this?
// TODO: simplify parentheses everywhere

impl Sha256 {
    pub fn new() -> Sha256 {
        Self { h: H_INIT }
    }

    fn process_block(&mut self, message: &[u32; 16]) {
        let mut w = [0u32; 64];
        for (t, v) in message.iter().enumerate() {
            w[t] = *v;
        }

        for t in 16..=63 {
            w[t] = Sha256::ssig1(w[t - 2]) + w[t - 7] + Sha256::ssig0(w[t - 15]) + w[t - 16]
        }

        let mut a = self.h[0];
        let mut b = self.h[1];
        let mut c = self.h[2];
        let mut d = self.h[3];
        let mut e = self.h[4];
        let mut f = self.h[5];
        let mut g = self.h[6];
        let mut h = self.h[7];

        for t in 0..=63 {
            let t1 = h + Sha256::bsig1(e) + Sha256::ch(e, f, g) + K_CONST[t] + w[t];
            let t2 = Sha256::bsig0(a) + Sha256::maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }

        self.h[0] += a;
        self.h[1] += b;
        self.h[2] += c;
        self.h[3] += d;
        self.h[4] += e;
        self.h[5] += f;
        self.h[6] += g;
        self.h[7] += h;
    }

    // region internal sha256 functions

    fn ch(x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (!x & z)
    }

    fn maj(x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (x & z) ^ (y & z)
    }

    fn shr(x: u32, bits: u8) -> u32 {
        x >> bits
    }

    fn rotl(x: u32, bits: u8) -> u32 {
        (x << bits) | (x >> (32 - bits))
    }

    fn rotr(x: u32, bits: u8) -> u32 {
        (x >> bits) | (x << (32 - bits))
    }

    fn bsig0(x: u32) -> u32 {
        Sha256::rotr(x, 2) ^ Sha256::rotr(x, 13) ^ Sha256::rotr(x, 22)
    }

    fn bsig1(x: u32) -> u32 {
        Sha256::rotr(x, 6) ^ Sha256::rotr(x, 11) ^ Sha256::rotr(x, 25)
    }

    fn ssig0(x: u32) -> u32 {
        Sha256::rotr(x, 7) ^ Sha256::rotr(x, 18) ^ Sha256::shr(x, 3)
    }

    fn ssig1(x: u32) -> u32 {
        Sha256::rotr(x, 17) ^ Sha256::rotr(x, 19) ^ Sha256::shr(x, 10)
    }

    // endregion

    // TODO: currently multiple calls to update are not supported because
    // final header with size should only be done when finishing

    pub fn update_bytes(&mut self, data: &[u8]) {
        let mut data = data.to_vec();
        let input_len = (data.len() * 8) as u64; // length of input in bits

        data.push(0x80);
        while (data.len() * 8) % 512 < 448 {
            data.push(0x00);
        }

        // Push length
        let bytes = input_len.to_be_bytes();
        data.extend_from_slice(&bytes);

        assert_eq!((data.len() * 8) % 512, 0);

        // Convert u8 to u32
        let data = data
            .chunks_exact(4)
            .map(|chunk| u32::from_be_bytes(chunk.try_into().unwrap()))
            .collect::<Vec<u32>>();

        // Convert u32 into blocks and process them.
        for chunk in data.chunks_exact(16) {
            let block: &[u32; 16] = chunk.try_into().unwrap();
            self.process_block(block);
        }
    }

    pub fn update_string(&mut self, data: &str) {
        self.update_bytes(data.as_bytes())
    }

    pub fn finish(&self) -> [u8; 32] {
        let mut output = vec![];

        for v in self.h.iter() {
            output.extend_from_slice(&v.to_be_bytes());
        }

        output.try_into().unwrap()
    }

    pub fn finish_hex(&self) -> String {
        self.finish()
            .iter()
            .map(|b| format!("{:02x}", b))
            // TODO: can we make this with collect natively (with String type as target)
            .collect::<Vec<String>>()
            .join("")
    }
}

#[cfg(test)]
mod tests {
    use crate::Sha256;
    extern crate test;
    use test::Bencher;

    // TODO: replace with more extensive tests
    #[test]
    fn works_basic() {
        let mut sha = Sha256::new();
        sha.update_string("hello world");
        assert_eq!(
            sha.finish_hex(),
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        )
    }

    #[test]
    fn long_message() {
        let mut sha = Sha256::new();
        sha.update_string(
            "Hello this is a very long sentence, that will definitely need more \
        than one block, which is 8 * 32 bit aka 256 bit aka 32 byte/ascii chars.",
        );
        assert_eq!(
            sha.finish_hex(),
            "4dc94210307ed19e6eb1ca6a25f09b5e33e92530375c5ea70e85685b7789546d"
        )
    }

    #[test]
    fn empty() {
        let mut sha = Sha256::new();
        sha.update_bytes(&[]);
        assert_eq!(sha.finish_hex(), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    }

    #[bench]
    fn bench_single_block(b: &mut Bencher) {
        b.iter(|| {
            let mut sha = Sha256::new();
            sha.update_string("hallo");
            sha.finish_hex()
        })
    }
}
