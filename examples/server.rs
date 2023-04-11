use std::net::TcpListener;
use std::time::Duration;
use std::thread::sleep;

use clap::Parser;
use local_ip_address::local_ip;
use safenet::{server::http::start_server, APPSTATE};

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
    let local_ip = local_ip()?.to_string();
    let port = args.port;
    let sock =
        TcpListener::bind(format!("{local_ip}:{port}")).expect("could not bind on port 1800");
    start_server(sock);

    loop {
        sleep(Duration::from_secs(5));
    }

    Ok(())
}
