#![allow(dead_code)]
#![feature(test)]

use std::convert::TryInto;

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

pub struct Sha256 {
    h: [u32; 8],
    buf: Vec<u8>,
    len: u64,
}

impl Default for Sha256 {
    fn default() -> Self {
        Sha256::new()
    }
}

impl Sha256 {
    pub fn new() -> Self {
        Self {
            h: H_INIT,
            buf: vec![],
            len: 0,
        }
    }

    pub fn reset(&mut self) {
        self.h = H_INIT;
        self.buf.clear();
        self.len = 0;
    }

    pub fn update_bytes(&mut self, data: &[u8]) {
        self.len += (data.len() * 8) as u64;
        self.buf.extend_from_slice(data);

        // Divide buf into blocks of size 512 = 64 * 8
        let chunks = self.buf.chunks_exact(64);
        let rest = chunks.remainder().to_vec();

        let blocks = chunks
            .map(|block| Self::convert_u8_to_32(block).try_into().unwrap())
            .collect::<Vec<[u32; 16]>>();

        for block in blocks {
            self.process_block(&block)
        }

        self.buf = rest;
    }

    pub fn update_string(&mut self, data: &str) {
        self.update_bytes(data.as_bytes())
    }

    pub fn finish(&mut self) -> [u8; 32] {
        self.do_final_block();
        let mut output = vec![];

        for v in self.h.iter() {
            output.extend_from_slice(&v.to_be_bytes());
        }

        output.try_into().unwrap()
    }

    pub fn finish_hex(&mut self) -> String {
        self.finish().iter().map(|b| format!("{:02x}", b)).collect()
    }

    #[allow(clippy::many_single_char_names)] // this is sha256 and these names are used in the spec
    fn process_block(&mut self, message: &[u32; 16]) {
        let mut w = [0u32; 64];
        for (t, v) in message.iter().enumerate() {
            w[t] = *v;
        }

        for t in 16..=63 {
            w[t] = Self::ssig1(w[t - 2])
                .wrapping_add(w[t - 7].wrapping_add(Self::ssig0(w[t - 15]).wrapping_add(w[t - 16])))
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
            let t1 = h.wrapping_add(
                Self::bsig1(e).wrapping_add(
                    Self::ch(e, f, g)
                        .wrapping_add(K_CONST[t])
                        .wrapping_add(w[t]),
                ),
            );
            let t2 = Self::bsig0(a).wrapping_add(Self::maj(a, b, c));
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        self.h[0] = self.h[0].wrapping_add(a);
        self.h[1] = self.h[1].wrapping_add(b);
        self.h[2] = self.h[2].wrapping_add(c);
        self.h[3] = self.h[3].wrapping_add(d);
        self.h[4] = self.h[4].wrapping_add(e);
        self.h[5] = self.h[5].wrapping_add(f);
        self.h[6] = self.h[6].wrapping_add(g);
        self.h[7] = self.h[7].wrapping_add(h);
    }

    fn do_final_block(&mut self) {
        assert!(self.buf.len() < 56);

        // Push 1 finish signifier and pad missing zeros.
        self.buf.push(0x80);
        while self.buf.len() < 56 {
            self.buf.push(0);
        }

        // Push length (64 bit, 8 byte to fill buf to 64 bytes)
        let bytes = self.len.to_be_bytes();
        self.buf.extend_from_slice(&bytes);

        let last_block = Self::convert_u8_to_32(&self.buf);
        self.process_block(&last_block.try_into().unwrap());
    }

    fn convert_u8_to_32(data: &[u8]) -> Vec<u32> {
        data.chunks_exact(4) // 4 * 8 bits for 32 bits
            .map(|chunk| u32::from_be_bytes(chunk.try_into().unwrap()))
            .collect::<Vec<u32>>()
    }

    // region internal sha256 functions

    fn ch(x: u32, y: u32, z: u32) -> u32 {
        x & y ^ !x & z
    }

    fn maj(x: u32, y: u32, z: u32) -> u32 {
        x & y ^ x & z ^ y & z
    }

    fn shr(x: u32, bits: u8) -> u32 {
        x >> bits
    }

    fn rotl(x: u32, bits: u8) -> u32 {
        x << bits | x >> (32 - bits)
    }

    fn rotr(x: u32, bits: u8) -> u32 {
        x >> bits | x << (32 - bits)
    }

    fn bsig0(x: u32) -> u32 {
        Self::rotr(x, 2) ^ Self::rotr(x, 13) ^ Self::rotr(x, 22)
    }

    fn bsig1(x: u32) -> u32 {
        Self::rotr(x, 6) ^ Self::rotr(x, 11) ^ Self::rotr(x, 25)
    }

    fn ssig0(x: u32) -> u32 {
        Self::rotr(x, 7) ^ Self::rotr(x, 18) ^ Self::shr(x, 3)
    }

    fn ssig1(x: u32) -> u32 {
        Self::rotr(x, 17) ^ Self::rotr(x, 19) ^ Self::shr(x, 10)
    }

    // endregion
}

#[cfg(test)]
mod tests {
    extern crate test;

    use std::fs;
    use test::Bencher;

    use crate::Sha256;

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
        assert_eq!(
            sha.finish_hex(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
    }

    #[test]
    fn multiple_update_calls() {
        let mut sha = Sha256::new();
        sha.update_string("abc");
        sha.update_string("def");
        assert_eq!(
            sha.finish_hex(),
            "bef57ec7f53a6d40beb640a780a639c83bc29ac8a9816f1fc6c5c6dcd93c4721"
        )
    }

    #[test]
    fn numbers_to_1000() {
        let mut sha = Sha256::new();
        let expected_file_content = fs::read_to_string("./test_number_1000.txt")
            .expect("Couldn't read expected outputs from file");
        let expected = expected_file_content
            .split("\n")
            .filter(|line| !line.is_empty())
            .collect::<Vec<&str>>();

        for i in 0..=1000 {
            sha.reset();
            let input = format!("{}", i);
            sha.update_string(&input);
            let output = sha.finish_hex();
            assert_eq!(output, expected[i]);
        }
    }

    #[bench]
    fn bench_single_block(b: &mut Bencher) {
        let data = "hallo";
        let mut sha = Sha256::new();
        b.iter(|| {
            sha.reset();
            sha.update_string(data);
            let result = sha.finish_hex();
            assert_eq!(
                result,
                "d3751d33f9cd5049c4af2b462735457e4d3baf130bcbb87f389e349fbaeb20b9"
            )
        })
    }
}
