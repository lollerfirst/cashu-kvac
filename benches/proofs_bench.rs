#![feature(test)]
extern crate test;
use cashu_kvac::{
    bulletproof::BulletProof,
    generators::GENERATORS,
    models::{AmountAttribute, Coin, MintPrivateKey, RandomizedCoin, ScriptAttribute, MAC},
    secp::{GroupElement, Scalar},
    transcript::CashuTranscript,
};
use test::Bencher;

use cashu_kvac::kvac::{
    BalanceProof, BootstrapProof, IssuanceProof, MacProof, ScriptEqualityProof,
};

fn transcripts() -> (CashuTranscript, CashuTranscript) {
    let mint_transcript = CashuTranscript::new();
    let client_transcript = CashuTranscript::new();
    (mint_transcript, client_transcript)
}

fn privkey() -> MintPrivateKey {
    let scalars: Vec<Scalar> = (0..6).map(|_| Scalar::random()).collect();
    MintPrivateKey::from_scalars(&scalars).expect("Could not generate private key")
}

#[bench]
fn bench_bootstrap_proof(bencher: &mut Bencher) {
    let (_, mut client_transcript) = transcripts();
    let bootstrap_attr = AmountAttribute::new(0, None);
    bencher.iter(|| BootstrapProof::create(&bootstrap_attr, client_transcript.as_mut()));
}

#[bench]
fn bench_iparams_proof(bencher: &mut Bencher) {
    let mint_privkey = privkey();
    let amount_attr = AmountAttribute::new(12, None);
    let mac = MAC::generate(&mint_privkey, &amount_attr.commitment(), None, None)
        .expect("Couldn't generate MAC");
    bencher.iter(|| IssuanceProof::create(&mint_privkey, &mac, &amount_attr.commitment(), None));
}

#[bench]
fn bench_mac_proof(bencher: &mut Bencher) {
    let (_, mut client_transcript) = transcripts();
    let mint_privkey = privkey();
    let amount_attr = AmountAttribute::new(12, None);
    let mac = MAC::generate(&mint_privkey, &amount_attr.commitment(), None, None)
        .expect("Couldn't generate MAC");
    let coin = Coin::new(amount_attr, None, mac);
    let randomized_coin =
        RandomizedCoin::from_coin(&coin, false).expect("Expected a randomized coin");
    bencher.iter(|| {
        MacProof::create(
            &mint_privkey.public_key,
            &coin,
            &randomized_coin,
            &mut client_transcript,
        )
    });
}

#[bench]
fn bench_balance_proof(bencher: &mut Bencher) {
    let (_, mut client_transcript) = transcripts();
    let inputs = vec![
        AmountAttribute::new(12, None),
        AmountAttribute::new(11, None),
    ];
    let outputs = vec![AmountAttribute::new(23, None)];
    bencher.iter(|| BalanceProof::create(&inputs, &outputs, &mut client_transcript));
}

#[bench]
fn bench_script_proofs(bencher: &mut Bencher) {
    let (_, mut client_transcript) = transcripts();
    let script = b"testscript";
    let privkey = privkey();
    let inputs = vec![
        (
            AmountAttribute::new(12, None),
            ScriptAttribute::new(script, None),
        ),
        (
            AmountAttribute::new(11, None),
            ScriptAttribute::new(script, None),
        ),
    ];
    let outputs = vec![
        (
            AmountAttribute::new(6, None),
            ScriptAttribute::new(script, None),
        ),
        (
            AmountAttribute::new(11, None),
            ScriptAttribute::new(script, None),
        ),
    ];
    let macs: Vec<MAC> = inputs
        .iter()
        .map(|(amount_attr, script_attr)| {
            MAC::generate(
                &privkey,
                &amount_attr.commitment(),
                Some(&script_attr.commitment()),
                None,
            )
            .expect("")
        })
        .collect();
    let coins: Vec<Coin> = inputs
        .into_iter()
        .zip(macs)
        .map(|((aa, sa), mac)| Coin::new(aa, Some(sa), mac))
        .collect();
    let randomized_coins: Vec<RandomizedCoin> = coins
        .iter()
        .map(|coin| RandomizedCoin::from_coin(coin, false).expect(""))
        .collect();
    bencher.iter(|| {
        ScriptEqualityProof::create(
            &coins,
            &randomized_coins,
            &outputs,
            client_transcript.as_mut(),
        )
    });
}

#[bench]
fn bench_range_proof(bencher: &mut Bencher) {
    let mut cli_tscr = CashuTranscript::new();

    let attributes: Vec<AmountAttribute> = vec![
        AmountAttribute::new(14, None),
        AmountAttribute::new(1, None),
        AmountAttribute::new(11, None),
    ];
    let mut attribute_commitments = Vec::new();
    for attr in attributes.iter() {
        attribute_commitments.push((attr.commitment(), GENERATORS.O));
    }
    bencher.iter(|| BulletProof::new(&mut cli_tscr, &attributes));
}

#[bench]
fn bench_bootstrap_proof_verification(bencher: &mut Bencher) {
    let (mut mint_transcript, mut client_transcript) = transcripts();
    let bootstrap_attr = AmountAttribute::new(0, None);
    let proof = BootstrapProof::create(&bootstrap_attr, client_transcript.as_mut());
    bencher.iter(|| {
        BootstrapProof::verify(
            &bootstrap_attr.commitment(),
            proof.clone(),
            &mut mint_transcript,
        )
    });
}

#[bench]
fn bench_iparams_proof_verification(bencher: &mut Bencher) {
    let mint_privkey = privkey();
    let amount_attr = AmountAttribute::new(12, None);
    let mac = MAC::generate(&mint_privkey, &amount_attr.commitment(), None, None)
        .expect("Couldn't generate MAC");
    let proof = IssuanceProof::create(&mint_privkey, &mac, &amount_attr.commitment(), None);
    let coin = Coin::new(amount_attr, None, mac);
    bencher.iter(|| IssuanceProof::verify(&mint_privkey.public_key, &coin, proof.clone()));
}

#[bench]
fn bench_balance_proof_verification(bencher: &mut Bencher) {
    let (mut mint_transcript, mut client_transcript) = transcripts();
    let privkey = privkey();
    let inputs = vec![
        AmountAttribute::new(12, None),
        AmountAttribute::new(11, None),
    ];
    let outputs = vec![AmountAttribute::new(23, None)];
    // We assume the inputs were already attributed a MAC previously
    let macs: Vec<MAC> = inputs
        .iter()
        .map(|input| {
            MAC::generate(&privkey, &input.commitment(), None, None).expect("MAC expected")
        })
        .collect();
    let proof = BalanceProof::create(&inputs, &outputs, &mut client_transcript);
    let mut coins: Vec<Coin> = macs
        .into_iter()
        .zip(inputs)
        .map(|(mac, input)| Coin::new(input, None, mac))
        .collect();
    let randomized_coins: Vec<RandomizedCoin> = coins
        .iter_mut()
        .map(|coin| RandomizedCoin::from_coin(coin, false).expect("RandomzedCoin expected"))
        .collect();
    let outputs: Vec<GroupElement> = outputs
        .into_iter()
        .map(|output| output.commitment())
        .collect();
    bencher.iter(|| {
        BalanceProof::verify(
            &randomized_coins,
            &outputs,
            0,
            proof.clone(),
            &mut mint_transcript,
        )
    });
}

#[bench]
fn bench_mac_proof_verification(bencher: &mut Bencher) {
    let (mut mint_transcript, mut client_transcript) = transcripts();
    let mint_privkey = privkey();
    let amount_attr = AmountAttribute::new(12, None);
    let mac = MAC::generate(&mint_privkey, &amount_attr.commitment(), None, None)
        .expect("Couldn't generate MAC");
    let coin = Coin::new(amount_attr, None, mac);
    let randomized_coin =
        RandomizedCoin::from_coin(&coin, false).expect("Expected a randomized coin");
    let proof = MacProof::create(
        &mint_privkey.public_key,
        &coin,
        &randomized_coin,
        &mut client_transcript,
    );
    bencher.iter(|| {
        MacProof::verify(
            &mint_privkey,
            &randomized_coin,
            None,
            proof.clone(),
            &mut mint_transcript,
        )
    });
}

#[bench]
fn bench_script_proof_verification(bencher: &mut Bencher) {
    let (mut mint_transcript, mut client_transcript) = transcripts();
    let script = b"testscript";
    let privkey = privkey();
    let inputs = vec![
        (
            AmountAttribute::new(12, None),
            ScriptAttribute::new(script, None),
        ),
        (
            AmountAttribute::new(11, None),
            ScriptAttribute::new(script, None),
        ),
    ];
    let outputs = vec![
        (
            AmountAttribute::new(6, None),
            ScriptAttribute::new(script, None),
        ),
        (
            AmountAttribute::new(11, None),
            ScriptAttribute::new(script, None),
        ),
        (
            AmountAttribute::new(12, None),
            ScriptAttribute::new(script, None),
        ),
    ];
    let macs: Vec<MAC> = inputs
        .iter()
        .map(|(amount_attr, script_attr)| {
            MAC::generate(
                &privkey,
                &amount_attr.commitment(),
                Some(&script_attr.commitment()),
                None,
            )
            .expect("")
        })
        .collect();
    let coins: Vec<Coin> = inputs
        .into_iter()
        .zip(macs)
        .map(|((aa, sa), mac)| Coin::new(aa, Some(sa), mac))
        .collect();
    let randomized_coins: Vec<RandomizedCoin> = coins
        .iter()
        .map(|coin| RandomizedCoin::from_coin(coin, false).expect(""))
        .collect();
    let proof = ScriptEqualityProof::create(
        &coins,
        &randomized_coins,
        &outputs,
        client_transcript.as_mut(),
    )
    .expect("");
    let outputs: Vec<(GroupElement, GroupElement)> = outputs
        .into_iter()
        .map(|(aa, sa)| (aa.commitment(), sa.commitment()))
        .collect();
    bencher.iter(|| {
        ScriptEqualityProof::verify(
            &randomized_coins,
            &outputs,
            proof.clone(),
            mint_transcript.as_mut(),
        )
    });
}

#[bench]
fn bench_range_proof_verification(bencher: &mut Bencher) {
    let (mut mint_tscr, mut cli_tscr) = transcripts();

    let attributes: Vec<AmountAttribute> = vec![
        AmountAttribute::new(14, None),
        AmountAttribute::new(1, None),
        AmountAttribute::new(11, None),
    ];
    let mut attribute_commitments = Vec::new();
    for attr in attributes.iter() {
        attribute_commitments.push((attr.commitment(), GENERATORS.O));
    }
    let proof = BulletProof::new(&mut cli_tscr, &attributes);
    let mut attribute_commitments = Vec::new();
    for attr in attributes.iter() {
        attribute_commitments.push(attr.commitment());
    }
    bencher.iter(|| proof.clone().verify(&mut mint_tscr, &attribute_commitments));
}
