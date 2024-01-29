use criterion::{criterion_group, criterion_main, Criterion};
use safenet::{app_state::AppState, frame::InitFrame};
fn init_frame_enc(c: &mut Criterion) {
    AppState::init().unwrap();
    c.bench_function("init frame creation", |b| {
        b.iter(|| {
            InitFrame::default();
        })
    });
}

criterion_group!(benches, init_frame_enc);
criterion_main!(benches);
