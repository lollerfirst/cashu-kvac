#![feature(test)]

use cashu_kvac::{models::{AmountAttribute, Coin, MintPrivateKey, RandomizedCoin, ScriptAttribute, MAC}, secp::Scalar};
use test::Bencher;
extern crate test;

fn privkey() -> MintPrivateKey {
    let scalars = vec![Scalar::random(); 6];
    MintPrivateKey::from_scalars(&scalars).expect("Could not generate private key")
}

#[bench]
fn bench_mint_privatekey_generation(bencher: &mut Bencher) {
    let scalars = vec![Scalar::random(); 6];
    bencher.iter(|| MintPrivateKey::from_scalars(&scalars).expect("Could not generate private key"));
}

#[bench]
fn bench_attribute_generation(bencher: &mut Bencher) {
    bencher.iter(|| AmountAttribute::new(10, None));
}

#[bench]
fn bench_mac_generation(bencher: &mut Bencher) {
    let mint_privkey = privkey();
    let amount_attr = AmountAttribute::new(10, None);
    let script_attr = ScriptAttribute::new(b"3c83", None);
    bencher.iter(|| MAC::generate(&mint_privkey, &amount_attr.commitment(), Some(&script_attr.commitment()), None));
}

#[bench]
fn bench_coin_randomization(bencher: &mut Bencher) {
    let mint_privkey = privkey();
    let amount_attr = AmountAttribute::new(10, None);
    let script_attr = ScriptAttribute::new(b"3c83", None);
    let mac = MAC::generate(&mint_privkey, &amount_attr.commitment(), Some(&script_attr.commitment()), None);
    let coin = Coin::new(amount_attr, Some(script_attr), mac.unwrap());
    bencher.iter(|| RandomizedCoin::from_coin(&coin, true));
}