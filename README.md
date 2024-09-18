# Safenet
##### A modern communication protocol built to withstand the presence of quantum computing.

Safenet is a new protocol, with the goal of being an alternative to HTTP(s).
You can use whatever network protocol you want, and you can use safenet on top of it.

Currently, Safenet has 3 encryption modes.

| | Signing   | Key Negotiation | Hashing (KDF) | Symmetrical Encryption |
|------------|-----------|-----------------|---------------|------------------------|
| Legacy     | ECDSA     | ECDH            | Blake2b       | ChaCha20Poly1305       |
| Kyber      | Kyber     | Kyber           | Blake2b       | ChaCha20Poly1305       |
| Kyber-Dith | Dilithium | Kyber           | Blake2b       | ChaCha20Poly1305       |


I suggest Kyber-Dilithium, since it is a form of PQE (Post Quantum Encryption).
This means it is resilient to attacks from quantum computers.

You could even layer it with HTTP, like so:

```rust
#[post("/echo")]
fn echo(bytes: &[u8]) -> Vec<u8> {
    let mut data_frame = DataFrame::from_bytes(bytes).unwrap();
    data_frame.decode_frame().unwrap(); // Panics if peers did not exchange Initialization Frames

    let msg = format!(
        "got msg: {}",
        std::str::from_utf8(&data_frame.body).unwrap()
    );

    log::debug!("{msg}");

    let mut res_data_frame = DataFrame::new(msg.as_bytes());
    res_data_frame
        .encode_frame(Uuid::from_bytes(data_frame.uuid.unwrap()))
        .unwrap(); // Panics if peers did not exchange Initialization Frames

    res_data_frame.to_bytes()
}
```
### Usage

Safenet is influenced by HTTP/2. It uses frames as the form of communication.
There are currently 2 frames. Initialization Frames and Data Frames.
When 2 peers connect, they both generate Initialization Frames and exchange them.
After this process, they will both have a shared secret key that is used for encryption.

In comes Data Frames, where general data is sent. You put your bytes into a Data Frame, encrypt it and send it off.
The target peer will then decrypt it.

It is required that both peers exchange Initialization Frames before they start sending Data Frames.

Here is an example of an HTTP server configuration: 

```rust
#[post("/conn/init")]
fn conn_init(bytes: &[u8]) -> Vec<u8> {
    let res = InitFrame::new(EncryptionType::KyberDith).from_peer(bytes);
    if let Ok(res) = res {
        res
    } else {
        "init failed!\n".as_bytes().to_vec()
    }
}

#[post("/api/echo")]
fn api_echo(bytes: &[u8]) -> Vec<u8> {
    let mut data_frame = DataFrame::from_bytes(bytes).unwrap();
    data_frame.decode_frame().unwrap();

    let msg = format!(
        "got msg: {}",
        std::str::from_utf8(&data_frame.body).unwrap()
    );

    log::debug!("{msg}");

    let mut res_data_frame = DataFrame::new(msg.as_bytes());
    res_data_frame
        .encode_frame(Uuid::from_bytes(data_frame.uuid.unwrap()))
        .unwrap();

    res_data_frame.to_bytes()
}
```

Checkout the [examples](https://github.com/mateocabanal/safenet/tree/main/examples) for full usage.


See my [blog](https://mateocabanal.ca) for more information.
