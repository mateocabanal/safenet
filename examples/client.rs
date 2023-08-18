use clap::Parser;
use dialoguer::Input;
use safenet::APPSTATE;

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
    simple_logger::SimpleLogger::new()
        .with_level(log::LevelFilter::Info)
        .env()
        .init()?;
    let args = Args::parse();
    APPSTATE.write()?.user_id = args.id.as_bytes().try_into()?;
    let peer = args.peer.parse()?;
    let mut result = safenet::client::http::start_tunnel(peer);
    while result.is_err() {
        log::debug!("could not connect to peer, sleeping 2 secs");
        std::thread::sleep(std::time::Duration::from_secs(2));
        result = safenet::client::http::start_tunnel(peer);
    }
    loop {
        let msg = Input::<String>::new().with_prompt("> ").interact_text()?;
        if msg == "quit" {
            break;
        };
        let res = safenet::client::http::echo_server(peer, &msg)?;
        println!("{}", res.as_str()?);
    }

    Ok(())
}
