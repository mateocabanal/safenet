use std::net::TcpListener;
use tinyhttp::prelude::Response;
use tinyhttp::prelude::Routes;

pub struct Config {
    routes: Option<Routes>,
    socket: Option<TcpListener>,
}
