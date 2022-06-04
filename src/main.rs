mod rc4;
mod stream;

use byteorder::{BigEndian, ReadBytesExt};
use std::io::{self, BufReader, Cursor, Error, ErrorKind, Read, Write};
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs,
};
use std::thread;
use structopt::StructOpt;

use crate::rc4::Rc4;
use crate::stream::{CryptoRead, CryptoWrite};

const SOCKS5_VER: u8 = 5;
const CMD_BIND: u8 = 1;
const ATYP_IPV4: u8 = 1;
const ATYPE_HOST: u8 = 3;
const ATYPE_IPV6: u8 = 4;

#[derive(StructOpt, Debug, Clone)]
#[structopt(name = "basic")]
struct Cfg {
    /// local address include port, listen only to this address if specified
    #[structopt(short = "l", default_value = "127.0.0.1:10888")]
    local_addr: String,

    /// ss server address include port
    #[structopt(short = "s")]
    server_addr: String,

    /// ss server password
    #[structopt(short = "p")]
    password: String,
}

fn handle_client(stream: TcpStream, cfg: Cfg) -> Result<(), Error> {
    handshake(stream.try_clone()?)?;
    connect(stream.try_clone()?, cfg)?;

    Ok(())
}

// +----+----------+----------+
// |VER | NMETHODS | METHODS  |
// +----+----------+----------+
// | 1  |    1     | 1 to 255 |
// +----+----------+----------+

// +----+--------+
// |VER | METHOD |
// +----+--------+
// | 1  |   1    |
// +----+--------+
fn handshake(stream: TcpStream) -> Result<(), Error> {
    let mut buf_reader = BufReader::new(stream);
    let ver = buf_reader.read_u8()?;
    if ver != SOCKS5_VER {
        return Err(Error::new(ErrorKind::Other, "not supported ver"));
    }
    let methods = buf_reader.read_u8()?;
    let mut buf = vec![0; methods as usize];
    buf_reader.read_exact(&mut buf[..])?;

    buf_reader.get_mut().write([SOCKS5_VER, 0].as_ref())?;
    Ok(())
}

// +----+-----+-------+------+----------+----------+
// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
// +----+-----+-------+------+----------+----------+
// | 1  |  1  | X'00' |  1   | Variable |    2     |
// +----+-----+-------+------+----------+----------+

// +----+-----+-------+------+----------+----------+
// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
// +----+-----+-------+------+----------+----------+
// | 1  |  1  | X'00' |  1   | Variable |    2     |
// +----+-----+-------+------+----------+----------+
fn connect(mut stream: TcpStream, cfg: Cfg) -> Result<(), Error> {
    let mut reader = BufReader::new(&stream);
    let mut buf = [0; 4];
    reader.read_exact(&mut buf)?;
    let (ver, cmd, atype) = (buf[0], buf[1], buf[3]);
    if ver != SOCKS5_VER {
        return Err(Error::new(ErrorKind::Other, "not supported ver"));
    }
    if cmd != CMD_BIND {
        return Err(Error::new(ErrorKind::Other, "not supported cmd"));
    }

    println!("atype {}", atype);
    let mut raw_addr = vec![atype];
    let addr = match atype {
        ATYP_IPV4 => {
            reader.read_exact(&mut buf)?;
            let ipv4 = IpAddr::V4(Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]));
            raw_addr.append(&mut buf[..].to_owned());
            let mut buf = [0; 2];
            reader.read_exact(&mut buf)?;
            raw_addr.append(&mut buf[..].to_owned());
            let port = Cursor::new(&buf).read_u16::<BigEndian>()?;
            Ok(SocketAddr::new(ipv4, port))
        }
        ATYPE_IPV6 => {
            let mut buf = [0; 18];
            reader.read_exact(&mut buf)?;
            raw_addr.append(&mut buf[..].to_owned());
            let ipv6 = IpAddr::V6(Ipv6Addr::new(
                Cursor::new(&buf[0..2]).read_u16::<BigEndian>()?,
                Cursor::new(&buf[2..4]).read_u16::<BigEndian>()?,
                Cursor::new(&buf[4..6]).read_u16::<BigEndian>()?,
                Cursor::new(&buf[6..8]).read_u16::<BigEndian>()?,
                Cursor::new(&buf[8..10]).read_u16::<BigEndian>()?,
                Cursor::new(&buf[10..12]).read_u16::<BigEndian>()?,
                Cursor::new(&buf[12..14]).read_u16::<BigEndian>()?,
                Cursor::new(&buf[14..16]).read_u16::<BigEndian>()?,
            ));
            let port = Cursor::new(&buf[16..]).read_u16::<BigEndian>()?;
            Ok(SocketAddr::new(ipv6, port))
        }
        ATYPE_HOST => {
            let host_byte = reader.read_u8()?;
            raw_addr.push(host_byte);
            let mut buf = vec![0; host_byte as usize];
            reader.read_exact(&mut buf)?;
            raw_addr.append(&mut buf[..].to_owned());
            Ok(String::from_utf8_lossy(&buf[..])
                .to_socket_addrs()?
                .next()
                .unwrap())
        }
        _ => Err(Error::new(ErrorKind::Other, "not supported atype")),
    };

    stream.write(&[SOCKS5_VER, 0, 0, 1, 0, 0, 0, 0, 0, 0])?;

    println!("start proxying");
    let mut stream_c = stream.try_clone()?;
    println!(
        "raw addr {:?}, proxy addr: {} by {}",
        raw_addr, addr?, cfg.server_addr
    );

    // proxy addr
    let dest = TcpStream::connect(cfg.server_addr)?;
    let dest_c = dest.try_clone()?;
    let mut thread_vec: Vec<thread::JoinHandle<()>> = Vec::new();
    // dest.set_nonblocking(true)?;

    let mut conn_r = CryptoRead::new(dest, Box::new(Rc4::new(&cfg.password.as_bytes())));
    let mut conn_w = CryptoWrite::new(dest_c, Box::new(Rc4::new(&cfg.password.as_bytes())));
    conn_w.write(&raw_addr)?;

    // let handle = thread::spawn(move || copy(stream, dest));
    // thread_vec.push(handle);

    // let handle = thread::spawn(move || copy(dest_c, stream_c));
    // thread_vec.push(handle);

    let handle = thread::spawn(move || match io::copy(&mut stream, &mut conn_w) {
        Ok(u) => println!("reader: stream, writer conn. copy {}", u),
        Err(e) => {
            println!("reader: stream, writer conn. err {}", e);
            conn_w.shutdown(Shutdown::Both).unwrap();
            stream.shutdown(Shutdown::Both).unwrap();
            drop(stream);
            drop(conn_w);
        }
    });
    thread_vec.push(handle);

    let handle = thread::spawn(move || match io::copy(&mut conn_r, &mut stream_c) {
        Ok(u) => println!("reader conn, writer stream. copy {}", u),
        Err(e) => {
            println!("reader conn, writer stream. err {}", e);
            conn_r.shutdown(Shutdown::Both).unwrap();
            stream_c.shutdown(Shutdown::Both).unwrap();
            drop(stream_c);
            drop(conn_r);
        }
    });
    thread_vec.push(handle);

    for handle in thread_vec {
        handle.join().unwrap();
    }
    Ok(())
}

fn main() -> std::io::Result<()> {
    let cfg = Cfg::from_args();
    println!("{:#?}", cfg);

    println!("listening {}", cfg.local_addr);
    let listener = TcpListener::bind(&cfg.local_addr)?;
    let mut thread_vec: Vec<thread::JoinHandle<()>> = Vec::new();

    for stream in listener.incoming() {
        println!("receive incoming connection");
        let stream = stream?;
        let cfg = cfg.clone();
        let handle = thread::spawn(move || {
            handle_client(stream, cfg).unwrap_or_else(|error| eprintln!("{:?}", error));
        });

        thread_vec.push(handle);
    }

    for handle in thread_vec {
        handle.join().unwrap();
    }

    Ok(())
}
