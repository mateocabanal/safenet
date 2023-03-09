use std::{collections::HashMap, net::TcpListener};

use tinyhttp::prelude::*;

use crate::APPSTATE;

#[get("/keys/pub")]
fn get_pub_key(_req: Request) -> Response {
    let server_pub_key = APPSTATE
        .read()
        .expect("Error getting read lock")
        .ecdsa_server_keys
        .pub_key
        .to_encoded_point(true);

    Response::new()
        .status_line("HTTP/1.1 200 OK")
        .body(server_pub_key.as_bytes().to_vec())
        .mime("application/octet-stream")
}

#[post("/init")]
fn init_conn(req: Request) -> Response {
    let body_bytes = req.get_raw_body();
    if body_bytes.len() < 52 {
        return Response::new()
            .body("nice try loser :)".as_bytes().to_vec())
            .status_line("403 Forbidden HTTP/1.1");
    }
    //let id = &body_bytes[0..=3];
    //let new_user_ecdsa_pub_key = &body_bytes[3..=52];
    Response::new()
        .status_line("HTTP/1.1 200 OK")
        .body(
            APPSTATE
                .read()
                .expect("Error getting read lock")
                .ecdsa_server_keys
                .pub_key
                .to_encoded_point(true)
                .as_bytes()
                .to_vec(),
        )
        .mime("fuck/off")
}

pub fn start_server(socket: TcpListener) {
    let routes = vec![init_conn(), get_pub_key()];
    let conf = Config::new().routes(Routes::new(routes));
    let http = HttpListener::new(socket, conf);
    http.start();
}
