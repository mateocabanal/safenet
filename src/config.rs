use std::net::TcpListener;
use tinyhttp::prelude::Response;
use tinyhttp::prelude::Routes;

pub struct Config {
    routes: Option<Routes>,
    socket: Option<TcpListener>,
}

impl Config {
    pub fn routes(mut self, routes: Routes) -> Self {
        for i in routes {
        };
        self.routes = Some(routes);
        self
    }
    pub fn start(self) {

        let config =
            tinyhttp::prelude::Config::new().routes(self.routes.expect("No routes provided!"));
        let http = tinyhttp::prelude::HttpListener::new(
            self.socket.expect("Obtaining socket failed"),
            config,
        );

        http.start();
    }
}
