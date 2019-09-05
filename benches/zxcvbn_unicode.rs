use criterion::black_box;
use criterion::Criterion;
use criterion::{criterion_group, criterion_main};

use zxcvbn::zxcvbn;

pub fn bench_zxcvbn_unicode(c: &mut Criterion) {
    c.bench_function("zxcvbn_unicode", |b| {
        b.iter(|| zxcvbn(black_box("𐰊𐰂𐰄𐰀𐰁"), &[]))
    });
}

criterion_group!(benches, bench_zxcvbn_unicode);
criterion_main!(benches);
