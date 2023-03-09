use tinyhttp::prelude::*;

#[post("/init")]
fn init_conn(req: Request) -> Response {
    let body_bytes = req.get_raw_body();
    if body_bytes.len() < 52 {
        return Response::new()
            .body("nice try loser :)".as_bytes().to_vec())
            .status_line("403 Forbidden HTTP/1.1");
    }
    let id = &body_bytes[0..=3];
    let ecdsa_pub_key = &body_bytes[3..=52];
    Response::new().status_line("200 OK HTTP/1.1").body(vec![]).mime("fuck/off")
}
