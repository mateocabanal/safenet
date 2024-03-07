use criterion::{criterion_group, criterion_main, Criterion};
use safenet::{
    app_state::AppState,
    frame::{EncryptionType, Frame, InitFrame},
    init_frame::kyber::KyberInitFrame,
};

fn init_frame_enc(c: &mut Criterion) {
    let _ = AppState::init();
    c.bench_function("legacy init frame negotiation", |b| {
        b.iter(|| {
            InitFrame::default()
                .from_peer(InitFrame::default().to_bytes())
                .unwrap();
        })
    });
}

fn init_frame_enc_kyber(c: &mut Criterion) {
    let _ = AppState::init();
    c.bench_function("kyber init frame negotiation", |b| {
        b.iter(|| {
            let mut client_frame = KyberInitFrame::new();
            let mut server_frame = KyberInitFrame::new();

            let server_pub_key = server_frame.from_peer(client_frame.to_bytes()).unwrap();
            let client_init = client_frame.from_peer(server_pub_key).unwrap();
            let server_recv = server_frame.from_peer(client_init).unwrap();
            client_frame.from_peer(server_recv).unwrap();
        })
    });
}

fn init_frame_enc_kyberdith(c: &mut Criterion) {
    let _ = AppState::init();
    c.bench_function("kyberdith init frame negotiation", |b| {
        b.iter(|| {
            InitFrame::new(EncryptionType::KyberDith)
                .from_peer(InitFrame::new(EncryptionType::KyberDith).to_bytes())
                .unwrap();
        })
    });
}

criterion_group!(
    benches,
    init_frame_enc,
    init_frame_enc_kyber,
    init_frame_enc_kyberdith
);
criterion_main!(benches);
