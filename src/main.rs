use ss::rc4::Rc4;
use ss::stream::{Rc4Reader, Rc4Writer};
use std::io::{Cursor, Error, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use structopt::StructOpt;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

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

async fn handle(mut stream: TcpStream, cfg: Cfg) -> Result<(), Error> {
    // handshake
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
    let ver = stream.read_u8().await?;
    if ver != SOCKS5_VER {
        return Err(Error::new(ErrorKind::Other, "not supported ver"));
    }
    let methods = stream.read_u8().await?;
    let mut buf = vec![0; methods as usize];
    stream.read_exact(&mut buf[..]).await?;

    stream.write([SOCKS5_VER, 0].as_ref()).await?;

    // connect
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
    let mut buf = [0; 4];
    stream.read_exact(&mut buf).await?;
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
            stream.read_exact(&mut buf).await?;
            let ipv4 = IpAddr::V4(Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]));
            raw_addr.append(&mut buf[..].to_owned());
            let mut buf = [0; 2];
            stream.read_exact(&mut buf).await?;
            raw_addr.append(&mut buf[..].to_owned());
            let port = Cursor::new(&buf).read_u16().await?;
            Ok(SocketAddr::new(ipv4, port))
        }
        ATYPE_IPV6 => {
            let mut buf = [0; 18];
            stream.read_exact(&mut buf).await?;
            raw_addr.append(&mut buf[..].to_owned());
            let ipv6 = IpAddr::V6(Ipv6Addr::new(
                Cursor::new(&buf[0..2]).read_u16().await?,
                Cursor::new(&buf[2..4]).read_u16().await?,
                Cursor::new(&buf[4..6]).read_u16().await?,
                Cursor::new(&buf[6..8]).read_u16().await?,
                Cursor::new(&buf[8..10]).read_u16().await?,
                Cursor::new(&buf[10..12]).read_u16().await?,
                Cursor::new(&buf[12..14]).read_u16().await?,
                Cursor::new(&buf[14..16]).read_u16().await?,
            ));
            let port = Cursor::new(&buf[16..]).read_u16().await?;
            Ok(SocketAddr::new(ipv6, port))
        }
        ATYPE_HOST => {
            let host_byte = stream.read_u8().await?;
            raw_addr.push(host_byte);
            let mut buf = vec![0; host_byte as usize];
            stream.read_exact(&mut buf).await?;
            raw_addr.append(&mut buf[..].to_owned());
            Ok(String::from_utf8_lossy(&buf[..])
                .to_socket_addrs()?
                .next()
                .unwrap())
        }
        _ => Err(Error::new(ErrorKind::Other, "not supported atype")),
    };

    stream
        .write(&[SOCKS5_VER, 0, 0, 1, 0, 0, 0, 0, 0, 0])
        .await?;

    println!("start proxying");
    println!(
        "raw addr {:?}, proxy addr: {} by {}",
        raw_addr, addr?, cfg.server_addr
    );

    // proxy addr
    let upstream = TcpStream::connect(cfg.server_addr).await?;

    let encryptor = Rc4::new(&cfg.password.as_bytes());
    let decryptor = Rc4::new(&cfg.password.as_bytes());

    let (rl, wl) = stream.into_split();
    let (ru, wu) = upstream.into_split();

    let mut ru = Rc4Reader::new(ru, Some(decryptor));
    let mut wl = Rc4Writer::new(wl, None);

    let mut rl = Rc4Reader::new(rl, None);
    let mut wu = Rc4Writer::new(wu, Some(encryptor));

    // write addr first
    wu.write(raw_addr.as_mut_slice()).await?;

    // copy bidirectional
    tokio::spawn(async move {
        // read from local and write to upstream
        copy1(&mut rl, &mut wu).await.unwrap();
    });

    // read from upstream and write to local
    copy1(&mut ru, &mut wl).await.unwrap();
    Ok(())
}

async fn copy1<'a, T: AsyncRead + Unpin, U: AsyncWrite + Unpin>(
    reader: &'a mut Rc4Reader<T>,
    writer: &'a mut Rc4Writer<U>,
) -> Result<(), Error> {
    let mut buf = [0; 1024];
    loop {
        let len = reader.read(&mut buf[..]).await?;

        if len == 0 {
            println!("break");
            break;
        } else {
            println!("read {} bytes", len);
        }

        writer.write(&mut buf[..len]).await?
    }
    Ok(())
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let cfg = Cfg::from_args();
    println!("config: {:#?}", cfg);

    println!("listening {}", cfg.local_addr);
    let listener = TcpListener::bind(&cfg.local_addr).await?;

    loop {
        let (stream, addr) = listener.accept().await?;
        let cfg = cfg.clone();
        println!("client {:?} connected", addr);
        tokio::spawn(async move {
            handle(stream, cfg).await.unwrap();
        });
    }
}
