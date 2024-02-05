use clap::Parser;
use dialoguer::Input;
use minreq::Request;
use safenet::{
    app_state::AppState,
    frame::{DataFrame, Frame, InitFrame},
    APPSTATE,
};
use uuid::Uuid;

#[derive(Parser, Debug)]
#[command(author, version)]
struct Args {
    #[arg(long)]
    peer: String,

    #[arg(short, long)]
    port: u32,

    #[arg(short, long)]
    id: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    AppState::init()?;
    simple_logger::SimpleLogger::new()
        .with_level(log::LevelFilter::Info)
        .env()
        .init()?;
    let args = Args::parse();
    APPSTATE.get().unwrap().write()?.user_id = args.id.as_bytes().try_into()?;
    let peer: String = args.peer.parse()?;

    let init_frame = InitFrame::default();
    println!("connecting to: {peer}");
    let mut result = minreq::post(format!("http://{peer}/conn/init"))
        .with_body(init_frame.to_bytes())
        .send();

    while result.is_err() {
        log::debug!("could not connect to peer, sleeping 2 secs");
        std::thread::sleep(std::time::Duration::from_secs(2));
        result = minreq::post(format!("http://{peer}/conn/init"))
            .with_body(init_frame.to_bytes())
            .send();
    }

    let server_init_frame_bytes = result.unwrap().into_bytes();
    if init_frame.from_peer(&server_init_frame_bytes).is_ok() {
        let peer_uuid = Uuid::from_slice(&server_init_frame_bytes[3..19])?;
        loop {
            let msg = Input::<String>::new().with_prompt("> ").interact_text()?;
            if msg == "quit" {
                break;
            };
            let mut data_frame = DataFrame::new(msg.as_bytes());
            data_frame.encode_frame(peer_uuid).unwrap();
            let res = minreq::post(format!("http://{peer}/echo"))
                .with_body(data_frame.to_bytes())
                .send()?;

            let mut server_res = DataFrame::from_bytes(res.as_bytes())?;

            server_res.decode_frame().unwrap();
            println!("{}", std::str::from_utf8(&server_res.body).unwrap());
        }
    }

    Ok(())
}
