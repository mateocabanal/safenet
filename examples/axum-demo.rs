use axum::{
    routing::get,
    Router, http::{Request, StatusCode}, body::{Bytes, Full}, response::Response,
};
use safenet::{frame::{InitFrame, Frame, DataFrame}, APPSTATE};

async fn init_conn(body_bytes: Bytes) -> Response<Full<Bytes>> {
    let init_frame = InitFrame::default();
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/plain")
        .body(init_frame.from_peer(&body_bytes).unwrap().into())
        .unwrap()
}

async fn echo(body_bytes: Bytes) -> Vec<u8> {
    let decrypted_frame = DataFrame::try_from(body_bytes.to_vec().into_boxed_slice()).unwrap();
    let msg = std::str::from_utf8(&decrypted_frame.body).unwrap();
    [b"Got: ", msg.as_bytes()].concat()
}

#[tokio::main]
async fn main() {
    // build our application with a single route
    let app = Router::new().route("/conn/init", get(init_conn)).route("/echo", get(echo));

    APPSTATE.try_write().unwrap().user_id = *b"ppp";

    // run it with hyper on localhost:3000
    axum::Server::bind(&"0.0.0.0:3000".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}
