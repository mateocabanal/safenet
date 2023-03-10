use hyper::client::Client;

pub async fn get_serv_pub() {
    let mut res = client.get("http://localhost:3698/keys/pub".parse().unwrap()).await;
    println!("res: {}", res.status());
}
