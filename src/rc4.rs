use md5::{Digest, Md5};
const MD5_LENGTH: u32 = 16;
const KEY_LEN: usize = 16;

#[derive(Debug)]
pub struct Rc4 {
    i: u8,
    j: u8,
    state: [u8; 256],
    password: Vec<u8>,
    init: bool,
}

impl Rc4 {
    // generates a new instance of RC4 by using the KSA (key-scheduling algorithm)
    pub fn new(password: &[u8]) -> Rc4 {
        Self {
            i: 0,
            j: 0,
            password: password.to_vec(),
            state: [0; 256],
            init: false,
        }
    }

    // returns `true` if RC4 is initialized
    pub fn is_init(&self) -> bool {
        self.init
    }

    // initialize RC4 instance with IV
    pub fn init(&mut self, iv: &[u8]) {
        let key = generate_rc4_key(&self.password, iv);

        for i in 0..256 {
            self.state[i] = i as u8;
        }

        let mut j: u8 = 0;
        for i in 0..256 {
            j = j
                .wrapping_add(self.state[i])
                .wrapping_add(key[i % key.len()]);
            self.state.swap(i, j as usize);
        }
        self.init = true;
    }

    // generates the next byte to be combined with a byte of the plain text / cipher.
    fn next_byte(&mut self) -> u8 {
        self.i = self.i.wrapping_add(1);
        self.j = self.j.wrapping_add(self.state[self.i as usize]);
        self.state.swap(self.i as usize, self.j as usize);
        self.state[self.state[self.i as usize].wrapping_add(self.state[self.j as usize]) as usize]
    }

    // uses KSA (new) and PRGA (next_byte) to XOR nput with the cipher
    pub fn crypt_inplace(&mut self, input: &mut [u8]) {
        for i in 0..input.len() {
            input[i] ^= self.next_byte();
        }
    }
}

pub fn compute(data: &[u8]) -> Vec<u8> {
    let mut hasher = Md5::new();
    hasher.update(data);
    let result = hasher.finalize();
    result.to_vec()
}

fn generate_rc4_key(password: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut hasher = Md5::new();
    let password = generate_key(password, KEY_LEN);
    hasher.update(&password);
    hasher.update(iv);
    let key = hasher.finalize();
    key.to_vec()
}

fn generate_key(data: &[u8], key_len: usize) -> Vec<u8> {
    let count = (key_len as f32 / MD5_LENGTH as f32).ceil() as u32;
    let mut key = Vec::from(&compute(data)[..]);
    let mut start = 0;
    for _ in 1..count {
        start += MD5_LENGTH;
        let mut d = Vec::from(&key[(start - MD5_LENGTH) as usize..start as usize]);
        d.extend_from_slice(data);
        let d = compute(d.as_slice());
        key.extend_from_slice(&*d);
    }
    key
}

#[cfg(test)]
mod tests {

    use super::{compute, generate_key, Rc4};

    #[test]
    fn compute_test() {
        let input = "hello";
        let v = compute(input.as_bytes());
        assert_eq!(
            &[93, 65, 64, 42, 188, 75, 42, 118, 185, 113, 157, 145, 16, 23, 197, 146],
            v.as_slice()
        )
    }

    #[test]
    fn generate_key_test() {
        let password = "password";
        let v = generate_key(password.as_bytes(), 16);
        println!("{:?}", v.as_slice());
    }

    #[test]
    fn zeor_bytes_test() {
        let mut v = [0u8; 10];

        let password = "password";
        let iv = "iv";
        let mut rc = Rc4::new(password.as_bytes());
        rc.init(iv.as_bytes());
        rc.crypt_inplace(v.as_mut_slice());
        println!("{:?}", v.as_slice());
        assert_eq!(
            &[208, 25, 195, 172, 214, 116, 6, 161, 235, 224],
            v.as_slice()
        );
    }
}
