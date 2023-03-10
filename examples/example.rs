use std::net::TcpListener;

fn main() {
    let client = hyper::client::Client::new();
    let sock = TcpListener::bind("0.0.0.0:3876").unwrap();
    std::thread::spawn(|| {
        safenet::server::http::start_server(sock);
    });
    safenet::client::http::get_serv_pub(client);
}
