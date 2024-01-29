use criterion::{criterion_group, criterion_main, Criterion};
use safenet::{
    app_state::AppState,
    frame::{DataFrame, Frame, InitFrame},
    APPSTATE,
};
fn data_frame_enc(c: &mut Criterion) {
    AppState::init().unwrap();
    InitFrame::default()
        .from_peer(&InitFrame::default().to_bytes())
        .unwrap();

    c.bench_function("data frame encryption (5 byte payload)", |b| {
        b.iter(|| {
            let mut frame = DataFrame::new(vec![78, 78, 78, 78, 78].as_slice());
            frame
                .encode_frame(APPSTATE.get().unwrap().read().unwrap().uuid)
                .unwrap();
        })
    });
}

criterion_group!(benches, data_frame_enc);
criterion_main!(benches);
