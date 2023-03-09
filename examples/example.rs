use std::net::TcpListener;

fn main() {
    let sock = TcpListener::bind("0.0.0.0:3876").unwrap();
    safenet::server::http::start_server(sock);
}
