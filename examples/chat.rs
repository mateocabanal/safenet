use std::net::TcpListener;

use local_ip_address::local_ip;
use safenet::{server::http::start_server, APPSTATE};
use clap::Parser;
use dialoguer::Input;

#[derive(Parser, Debug)]
#[command(author, version)]
struct Args {
    #[arg(long)]
    peer: String,

    #[arg(short, long)]
    port: u32,

    #[arg(short, long)]
    id: String
}

#[allow(unreachable_code)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    simple_logger::SimpleLogger::new().with_level(log::LevelFilter::Info).env().init()?;
    let local_ip = local_ip()?.to_string();
    let args = Args::parse();
    let port = args.port;
    let sock = TcpListener::bind(format!("{local_ip}:{port}")).expect("could not bind on port 1800");
    start_server(sock);
    APPSTATE.write()?.user_id = args.id.as_bytes().try_into()?;
    let peer = args.peer.parse()?;
    let mut result = safenet::client::http::start_tunnel(peer);
    while result.is_err() {
        log::debug!("could not connect to peer, sleeping 2 secs");
        std::thread::sleep(std::time::Duration::from_secs(2));
        result = safenet::client::http::start_tunnel(peer);
    };
    loop {
        let msg = Input::<String>::new()
            .with_prompt("> ")
            .interact_text()?;
        if msg == "quit" {
            break;
        };
        safenet::client::http::msg(peer, &msg)?;
    }

    Ok(()) 
}
