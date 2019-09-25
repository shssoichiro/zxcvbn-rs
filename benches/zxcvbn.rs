use criterion::black_box;
use criterion::Criterion;
use criterion::{criterion_group, criterion_main};

use zxcvbn::zxcvbn;

pub fn bench_zxcvbn(c: &mut Criterion) {
    c.bench_function("zxcvbn", |b| {
        b.iter(|| zxcvbn(black_box("r0sebudmaelstrom11/20/91aaaa"), &[]))
    });
}

criterion_group!(benches, bench_zxcvbn);
criterion_main!(benches);
