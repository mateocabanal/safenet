use std::{net::TcpListener, thread::sleep, time::Duration};

use safenet::APPSTATE;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    simple_logger::SimpleLogger::new().with_level(log::LevelFilter::Info).env().init()?;
    let sock = TcpListener::bind("127.0.0.1:3876").unwrap();
    safenet::server::http::start_server(sock);

    while !APPSTATE.read().unwrap().is_http_server_on {
        log::debug!("WAITING FOR SERVER...");
        sleep(Duration::from_millis(2000));
    }

//    safenet::client::http::get_serv_pub();
    safenet::client::http::start_tunnel("127.0.0.1:3876".parse()?);
    safenet::client::http::msg("127.0.0.1:3876".parse()?, "hello server!");
    Ok(())
}
