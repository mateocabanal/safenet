use criterion::{criterion_group, criterion_main, Criterion};
use safenet::frame::InitFrame;
fn init_frame_enc(c: &mut Criterion) {
    c.bench_function("init frame creation", |b| {
        b.iter(|| {
            InitFrame::default();
        })
    });
}

criterion_group!(benches, init_frame_enc);
criterion_main!(benches);
