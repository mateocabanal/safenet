// #![deny(warnings)]
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use futures_util::{SinkExt, StreamExt, TryFutureExt};
use safenet::app_state::AppState;
use safenet::frame::{DataFrame, EncryptionType, Frame, FrameType, InitFrame, Options};
use safenet::APPSTATE;
use safenet::init_frame::kyber::KyberInitFrame;
use tokio::sync::{mpsc, RwLock};
use tokio_stream::wrappers::UnboundedReceiverStream;
use uuid::Uuid;
use warp::ws::{Message, WebSocket};
use warp::Filter;

/// Our global unique user id counter.
static NEXT_USER_ID: AtomicUsize = AtomicUsize::new(1);

/// Our state of currently connected users.
///
/// - Key is their id
/// - Value is a sender of `warp::ws::Message`
type Users = Arc<RwLock<HashMap<Uuid, mpsc::UnboundedSender<Message>>>>;

#[tokio::main]
async fn main() {
    // Keep track of all connected users, key is usize, value
    // is a websocket sender.
    use warp::http::header::{HeaderMap, HeaderValue};

    simple_logger::SimpleLogger::new()
        .with_level(log::LevelFilter::Info)
        .env()
        .init()
        .unwrap();

    if Path::new("./privkey.der").exists() {
        let mut priv_bytes = vec![];
        let mut priv_file = File::open("./privkey.der").unwrap();
        priv_file.read_to_end(&mut priv_bytes).unwrap();
        AppState::init_with_priv_key(&priv_bytes).unwrap();
    } else {
        log::info!("creating ECDSA keys");
        AppState::init().unwrap();
        let mut priv_file = File::create("./privkey.der").unwrap();
        priv_file
            .write_all(&APPSTATE.get().unwrap().read().unwrap().priv_key_to_bytes())
            .unwrap();
    }

    log::debug!(
        "ECDSA key: {:?}",
        APPSTATE
            .get()
            .unwrap()
            .read()
            .unwrap()
            .server_keys
            .ecdsa
            .get_pub_key()
    );

    let users = Users::default();
    // Turn our "state" into a new Filter...
    let users = warp::any().map(move || users.clone());

    // GET /chat -> websocket upgrade
    let chat = warp::path("echo")
        // The `ws()` filter will prepare Websocket handshake...
        .and(warp::ws())
        .and(users)
        .map(|ws: warp::ws::Ws, users| {
            // This will call our function if the handshake succeeds.
            ws.on_upgrade(move |socket| user_connected(socket, users))
        });

    let conn_init = warp::path!("conn" / "init")
        .and(warp::post())
        .and(warp::body::bytes())
        .map(|body_bytes: warp::hyper::body::Bytes| {
            let init_frame = InitFrame::default();
            warp::reply::Response::new(init_frame.from_peer(&body_bytes).unwrap().into())
        })
        .with(warp::reply::with::header(
            "access-control-allow-origin",
            "*",
        ));

    let index = warp::path::end().and(warp::fs::dir("safenet_wasm_demo"));

    // GET / -> index html

    let routes = index
        .or(chat)
        .or(conn_init)
        .or(warp::fs::dir("safenet_wasm_demo"));

    warp::serve(routes).run(([0, 0, 0, 0], 42069)).await;
}

async fn user_connected(ws: WebSocket, users: Users) {
    // Use a counter to assign a new unique ID for this user.

    // Split the socket into a sender and receive of messages.
    let (mut user_ws_tx, mut user_ws_rx) = ws.split();

    // Must read uuid off rip

    let req_bytes = user_ws_rx.next().await.unwrap().unwrap().into_bytes();
    let my_id = Uuid::from_slice(&req_bytes[3..19]).unwrap();

    let options_len = u32::from_be_bytes(req_bytes[19..=22].try_into().unwrap());
    log::debug!("options len: {options_len}");
    let options_arr = &req_bytes[23..23 + options_len as usize];
    let frame_opts = Options::try_from(options_arr).unwrap();

    let frame_type = frame_opts.get_frame_type();
    if frame_type == FrameType::Init {
        let init_opts = frame_opts.get_init_opts().unwrap();

        match init_opts.get_encryption_type().unwrap() {
            EncryptionType::Legacy => {
                let res_body = InitFrame::default().from_peer(&req_bytes).unwrap();
                user_ws_tx.send(Message::binary(res_body)).await.unwrap();
            }
            EncryptionType::Kyber => {
                let mut server_kyber_frame = KyberInitFrame::new();
                let server_pub_key = server_kyber_frame.from_peer(req_bytes).unwrap();
                user_ws_tx.send(Message::binary(server_pub_key)).await.unwrap();
                let client_init = user_ws_rx.next().await.unwrap().unwrap().into_bytes();

                let server_recv = server_kyber_frame.from_peer(&client_init).unwrap();
                user_ws_tx.send(Message::binary(server_recv)).await.unwrap();

                log::debug!("kyber shared secret: {:?}", server_kyber_frame.kyber.cipher.shared_secret);
            }
        }
    }

    if let Some(addr) = frame_opts.get_ip_addr() {
        log::debug!("user ip: {}", addr);
    }
    println!("new chat user: {}", my_id);
    // Use an unbounded channel to handle buffering and flushing of messages
    // to the websocket...
    let (tx, rx) = mpsc::unbounded_channel();
    let mut rx = UnboundedReceiverStream::new(rx);

    tokio::task::spawn(async move {
        while let Some(message) = rx.next().await {
            user_ws_tx
                .send(message)
                .unwrap_or_else(|e| {
                    println!("websocket send error: {}", e);
                })
                .await;
        }
    });

    // Save the sender in our list of connected users.
    users.write().await.insert(my_id, tx);

    // Return a `Future` that is basically a state machine managing
    // this specific user's connection.

    // Every time the user sends a message, broadcast it to
    // all other users...
    while let Some(result) = user_ws_rx.next().await {
        let msg = match result {
            Ok(msg) => msg,
            Err(e) => {
                eprintln!("websocket error(uid={}): {}", my_id, e);
                break;
            }
        };
        user_message(my_id, msg, &users).await;
    }

    // user_ws_rx stream will keep processing as long as the user stays
    // connected. Once they disconnect, then...
    user_disconnected(my_id, &users).await;
}

async fn user_message(my_id: Uuid, msg: Message, users: &Users) {
    // Skip any non-Text messages...
    let recv_bytes = msg.into_bytes();
    let mut data_frame = DataFrame::try_from(recv_bytes.into_boxed_slice()).unwrap();
    data_frame.decode_frame().unwrap();
    let msg = String::from_utf8(data_frame.body.to_vec()).unwrap();

    let new_msg = format!("User {}: {}", my_id, msg);

    // New message from this user, send it to everyone else (except same uid)...
    for (&uid, tx) in users.read().await.iter() {
        let mut data_frame = DataFrame::new(&*new_msg.clone().into_bytes());
        data_frame.encode_frame(uid).unwrap();

        if let Err(_disconnected) = tx.send(Message::binary(data_frame.to_bytes())) {
            // The tx is disconnected, our `user_disconnected` code
            // should be happening in another task, nothing more to
            // do here.
        }
    }
}

async fn user_disconnected(my_id: Uuid, users: &Users) {
    eprintln!("good bye user: {}", my_id);

    // Stream closed up, so remove from the user list
    users.write().await.remove(&my_id);
}

static INDEX_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
    <head>
        <title>Warp Chat</title>
    </head>
    <body>
        <h1>Warp chat</h1>
        <div id="chat">
            <p><em>Connecting...</em></p>
        </div>
        <input type="text" id="text" />
        <button type="button" id="send">Send</button>
        <script type="text/javascript">
        const chat = document.getElementById('chat');
        const text = document.getElementById('text');
        const uri = 'ws://' + location.host + '/chat';
        const ws = new WebSocket(uri);

        function message(data) {
            const line = document.createElement('p');
            line.innerText = data;
            chat.appendChild(line);
        }

        ws.onopen = function() {
            chat.innerHTML = '<p><em>Connected!</em></p>';
        };

        ws.onmessage = function(msg) {
            message(msg.data);
        };

        ws.onclose = function() {
            chat.getElementsByTagName('em')[0].innerText = 'Disconnected!';
        };

        send.onclick = function() {
            const msg = text.value;
            ws.send(msg);
            text.value = '';

            message('<You>: ' + msg);
        };
        </script>
    </body>
</html>
"#;
