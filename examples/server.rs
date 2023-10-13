use std::net::{IpAddr, SocketAddr, TcpListener};
use std::thread::sleep;
use std::time::Duration;

use clap::Parser;
use local_ip_address::local_ip;
use safenet::{
    frame::{DataFrame, Frame, InitFrame},
    uuid::Uuid,
    APPSTATE,
};
use tinyhttp::prelude::*;

#[post("/conn/init")]
fn conn_init(req: Request) -> Response {
    let req_bytes = req.get_raw_body();
    let init_frame = InitFrame::default();
    Response::new()
        .mime("text/plain")
        .body(init_frame.from_peer(req_bytes).unwrap())
        .mime("HTTP/1.1 200 OK")
}

#[post("/echo")]
fn server_msg(req: Request) -> Response {
    let req_bytes = req.get_raw_body().clone();
    let data_frame: Result<DataFrame, String> = req_bytes.into_boxed_slice().try_into();
    if data_frame.is_err() {
        log::trace!("failed to parse data frame");
        return Response::new()
            .body(vec![])
            .mime("fuck/off")
            .status_line("HTTP/1.1 42069 fuck_u");
    }
    let mut data_frame = data_frame.expect("failed to parse data");

    let dec_body = data_frame.decode_frame();

    if let Err(e) = dec_body {
        log::error!("failed to decrypt frame: {e}");
        Response::new()
            .body(vec![])
            .mime("fuck/u")
            .status_line("HTTP/1.1 42069 fuck_me")
    } else {
        let msg = std::str::from_utf8(&data_frame.body).unwrap();
        let mut response_frame = DataFrame::new(&*format!("got: {msg}").into_bytes());
        response_frame
            .encode_frame(Uuid::from_bytes(data_frame.uuid.unwrap()))
            .unwrap();
        Response::new()
            .body(response_frame.to_bytes())
            .mime("love/u")
            .status_line("HTTP/1.1 200 OK")
    }
}

#[derive(Parser, Debug)]
#[command(author, version)]
struct Args {
    #[arg(short, long)]
    port: u32,

    #[arg(short, long)]
    id: String,
}

#[allow(unreachable_code)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    simple_logger::SimpleLogger::new()
        .with_level(log::LevelFilter::Info)
        .env()
        .init()?;
    let args = Args::parse();
    APPSTATE.write()?.user_id = args.id.as_bytes().try_into()?;
    let local_ip = local_ip()?;
    let port = args.port;
    let sock = TcpListener::bind(format!("0.0.0.0:{port}")).expect("could not bind on port 1800");
    APPSTATE
        .write()
        .expect("failed to get write lock")
        .server_addr = Some(SocketAddr::new(
        IpAddr::V4(local_ip.to_string().parse().unwrap()),
        args.port.try_into().unwrap(),
    ));
    let conf = Config::new().routes(Routes::new(vec![conn_init(), server_msg()]));
    let http = HttpListener::new(sock, conf);

    std::thread::spawn(|| http.start());
    loop {
        sleep(Duration::from_secs(5));
    }

    Ok(())
}
