use std::net::TcpListener;

use safenet::{server::http::start_server, APPSTATE};
use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version)]
struct Args {
    #[arg(short, long)]
    peer: String,

    #[arg(short, long)]
    id: String
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    simple_logger::SimpleLogger::new().with_level(log::LevelFilter::Info).env().init()?;
    let sock = TcpListener::bind("0.0.0.0:1800").expect("could not bind on port 1800");
    start_server(sock);
    let args = Args::parse();
    APPSTATE.write()?.user_id = args.id.as_bytes().try_into()?;
    let peer = args.peer.parse()?;
    let mut result = safenet::client::http::start_tunnel(peer);
    while result.is_err() {
        log::debug!("could not connect to peer, sleeping 2 secs");
        std::thread::sleep(std::time::Duration::from_secs(2));
        result = safenet::client::http::start_tunnel(peer);
    };
    loop {
        let mut msg = String::new();
        std::io::stdin().read_line(&mut msg)?;
        safenet::client::http::msg(peer, &msg);
    }

    Ok(()) 
}
