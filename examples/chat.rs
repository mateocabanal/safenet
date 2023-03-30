use std::net::TcpListener;

use safenet::{server::http::start_server, APPSTATE};
use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version)]
struct Args {
    #[arg(short, long)]
    peer: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
//    simple_logger::SimpleLogger::new().with_level(log::LevelFilter::Info).env().init()?;
    let sock = TcpListener::bind("0.0.0.0:1800").expect("could not bind on port 1800");
    start_server(sock);
    let args = Args::parse();
    let peer = args.peer.parse()?;
    safenet::client::http::start_tunnel(peer);
    let mut msg = String::new();
    loop {
        std::io::stdin().read_line(&mut msg)?;
        safenet::client::http::msg(peer, &msg);
    }

    Ok(()) 
}
