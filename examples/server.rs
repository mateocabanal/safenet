use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{mpsc, Arc, Mutex, OnceLock, RwLock};
use std::thread::sleep;
use std::time::Duration;

use clap::Parser;
use local_ip_address::local_ip;
use safenet::frame::{FrameType, Options};
use safenet::{
    frame::{DataFrame, Frame, InitFrame},
    uuid::Uuid,
    APPSTATE,
};
use tinyhttp::prelude::*;
use tungstenite::{accept, accept_hdr, handshake, Message, WebSocket};

#[get("/http/test")]
fn http_test() -> &'static str {
    "HTTP is working!\n"
}

#[post("/conn/init")]
fn conn_init(req: Request) -> Response {
    let req_bytes = req.get_raw_body();
    let init_frame = InitFrame::default();
    let init_frame_bytes = init_frame.from_peer(req_bytes);

    if let Ok(bytes) = init_frame_bytes {
        Response::new()
            .mime("application/octet-stream")
            .body(bytes)
            .status_line("HTTP/1.1 200 OK")
    } else {
        Response::new()
            .mime("text/plain")
            .body(vec![])
            .status_line("HTTP/1.1 200 OK")
    }
}

#[post("/echo")]
fn server_msg(req: Request) -> Response {
    let req_bytes = req.get_raw_body().clone();
    let data_frame: Result<DataFrame, String> = req_bytes.into_boxed_slice().try_into();
    if data_frame.is_err() {
        log::trace!("failed to parse data frame");
        return Response::new()
            .body(vec![])
            .mime("text/plain")
            .status_line("HTTP/1.1 451 Unavailable For Legal Reasons");
    }
    let mut data_frame = data_frame.expect("failed to parse data");

    let dec_body = data_frame.decode_frame();

    if let Err(e) = dec_body {
        log::error!("failed to decrypt frame: {e}");
        Response::new()
            .body(vec![])
            .mime("text/plain")
            .status_line("HTTP/1.1 451 Unavailable For Legal Reasons")
    } else {
        let msg = std::str::from_utf8(&data_frame.body).unwrap();
        let mut response_frame = DataFrame::new(format!("got: {msg}").into_bytes().as_slice());
        response_frame
            .encode_frame(Uuid::from_bytes(data_frame.uuid.unwrap()))
            .unwrap();
        Response::new()
            .body(response_frame.to_bytes())
            .mime("application/octet-stream")
            .status_line("HTTP/1.1 200 OK")
    }
}

fn ws_conn_init(req_bytes: Vec<u8>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    InitFrame::default().from_peer(&req_bytes)
}

fn ws_data(req_bytes: Vec<u8>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut data_frame: DataFrame = req_bytes.into_boxed_slice().try_into()?;
    data_frame.decode_frame()?;
    let msg = std::str::from_utf8(&data_frame.body)?;
    let mut res_frame = DataFrame::new(format!("got (ws): {msg}").as_bytes());
    res_frame
        .encode_frame(Uuid::from_bytes(data_frame.uuid.unwrap()))
        .unwrap();
    Ok(res_frame.to_bytes())
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
    let clients = Arc::new(Mutex::new(Vec::new()));
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
    let conf = Config::new()
        .routes(Routes::new(vec![conn_init(), server_msg(), http_test()]))
        .headers(vec!["Access-Control-Allow-Origin: *".into()]);
    let http = HttpListener::new(sock, conf);

    std::thread::spawn(|| http.start());
    // WebSockets
    let ws_socket = TcpListener::bind("0.0.0.0:42071").unwrap();
    for stream in ws_socket.incoming() {
        let app_state_clone = Arc::clone(&clients);
        std::thread::spawn(move || {
            let header_cb = |req: &handshake::server::Request,
                             mut res: handshake::server::Response| {
                log::debug!("uri: {}", req.uri().path());

                Ok(res)
            };

            let mut websocket = accept_hdr(stream.unwrap(), header_cb).unwrap();

            if let Ok(req) = websocket.read() {
                let mut app_state = app_state_clone.lock().unwrap();
                app_state.push(websocket);
                if req.is_binary() {
                    let req_bytes = req.into_data();
                    let options_len = u32::from_be_bytes(req_bytes[19..=22].try_into().unwrap());
                    log::debug!("options len: {options_len}");
                    let options_arr = &req_bytes[23..23 + options_len as usize];
                    let frame_opts = Options::try_from(options_arr).unwrap();

                    let frame_type = frame_opts.get_frame_type();
                    log::debug!("frame_type: {:?}", frame_type);

                    let res_bytes = match frame_type {
                        FrameType::Init => ws_conn_init(req_bytes),
                        FrameType::Data => ws_data(req_bytes),
                    };

                    if let Ok(res_bytes) = res_bytes {
                        let msg = Message::Binary(res_bytes);
                        let mut failed_socks = vec![];
                        let mut client_num = 0;
                        for (idx, client) in app_state.iter_mut().enumerate() {
                            client_num += 1;
                            if client.send(msg.clone()).is_err() {
                                failed_socks.push(idx);
                            }
                        }
                        log::debug!("clients: {client_num}");
                        for idx in failed_socks {
                            app_state.remove(idx);
                        }
                    };
                }
            }
        });
    }

    loop {
        sleep(Duration::from_secs(5));
    }

    Ok(())
}
