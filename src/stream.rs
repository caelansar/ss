use crate::rc4::Rc4;
use rand::Rng;
use std::{
    io::{Read, Write},
    ops::Deref,
};

const IV_LEN: usize = 16;

pub struct CryptoRead<R: Read> {
    conn_r: R,
    dec: Box<Rc4>,
}

impl<R: Read> CryptoRead<R> {
    pub fn new(conn_r: R, dec: Box<Rc4>) -> Self {
        Self { conn_r, dec }
    }
}

impl<R: Read> Deref for CryptoRead<R> {
    type Target = R;

    fn deref(&self) -> &Self::Target {
        &self.conn_r
    }
}

impl<R: Read> Read for CryptoRead<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
        println!("read: {:?}", buf);
        if !self.dec.is_init() {
            println!("init dec");
            let mut iv = [0; IV_LEN];
            self.conn_r.read_exact(&mut iv)?;
            println!("read iv: {:?}", iv);
            self.dec.init(&iv[..]);
        }
        let n = self.conn_r.read(buf)?;
        if n > 0 {
            // decrypt
            self.dec.crypt_inplace(buf[..n].as_mut())
        }
        println!("read {} byte", n);
        Ok(n)
    }
}

pub struct CryptoWrite<W: Write> {
    conn_w: W,
    enc: Box<Rc4>,
}

impl<W: Write> CryptoWrite<W> {
    pub fn new(conn_w: W, enc: Box<Rc4>) -> Self {
        Self { conn_w, enc }
    }
}

impl<W: Write> Deref for CryptoWrite<W> {
    type Target = W;

    fn deref(&self) -> &Self::Target {
        &self.conn_w
    }
}

impl<W: Write> Write for CryptoWrite<W> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, std::io::Error> {
        println!("write: {:?}", buf);
        let mut iv_o: Option<Vec<u8>> = None;
        if !self.enc.is_init() {
            println!("init enc");
            let iv = generate_iv();
            iv_o = Some(iv.clone());
            self.enc.init(&iv[..]);
        }
        let mut data: Vec<u8> = Vec::new();
        if let Some(mut iv) = iv_o {
            println!("append iv {:?}", iv);
            data.append(&mut iv);
        }
        let mut buf = buf.to_vec();
        // encrypt
        self.enc.crypt_inplace(&mut buf[..]);
        data.append(&mut buf);
        println!("write data {:?}", data);
        let n = self.conn_w.write(data.as_mut_slice())?;
        Ok(n)
    }

    fn flush(&mut self) -> Result<(), std::io::Error> {
        self.conn_w.flush()
    }
}

fn generate_iv() -> Vec<u8> {
    let random_bytes = rand::thread_rng().gen::<[u8; IV_LEN]>();
    random_bytes.to_vec()
}
