#![feature(test)]
extern crate test;
use cashu_kvac::generators::hash_to_curve;
use cashu_kvac::secp::Scalar;
use test::Bencher;

#[bench]
fn scalar_bench_add(bencher: &mut Bencher) {
    let a = Scalar::random();
    let b = Scalar::random();
    bencher.iter(|| a + &b);
}

#[bench]
fn scalar_bench_neg(bencher: &mut Bencher) {
    let a = Scalar::random();
    bencher.iter(|| -a);
}

#[bench]
fn scalar_bench_sub(bencher: &mut Bencher) {
    let a = Scalar::random();
    let b = Scalar::random();
    bencher.iter(|| a - &b);
}

#[bench]
fn scalar_bench_mul(bencher: &mut Bencher) {
    let a = Scalar::random();
    let b = Scalar::random();
    bencher.iter(|| a * &b);
}

#[bench]
fn scalar_bench_invert(bencher: &mut Bencher) {
    let a = Scalar::random();
    bencher.iter(|| a.invert());
}

#[bench]
fn scalar_bench_random(bencher: &mut Bencher) {
    bencher.iter(Scalar::random);
}

#[bench]
fn hash_to_curve_bench(bencher: &mut Bencher) {
    bencher.iter(|| hash_to_curve(b"test_groupelement"))
}

#[bench]
fn ge_bench_add(bencher: &mut Bencher) {
    let g1 = hash_to_curve(b"g1").unwrap();
    let g2 = hash_to_curve(b"g2").unwrap();
    bencher.iter(|| g1 + &g2);
}

#[bench]
fn ge_bench_sub(bencher: &mut Bencher) {
    let g1 = hash_to_curve(b"g1").unwrap();
    let g2 = hash_to_curve(b"g2").unwrap();
    bencher.iter(|| g1 - &g2);
}

#[bench]
fn ge_bench_mul(bencher: &mut Bencher) {
    let a = Scalar::random();
    let g1 = hash_to_curve(b"g1").unwrap();
    bencher.iter(|| g1 * &a);
}

#[bench]
fn ge_bench_mul_unmasked(bencher: &mut Bencher) {
    let a = Scalar::random();
    let g1 = hash_to_curve(b"g1").unwrap();
    bencher.iter(|| {
        let mut g = g1;
        g.multiply(&a);
    });
}
