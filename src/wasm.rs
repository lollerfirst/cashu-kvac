//! Module used to bridge the interface of cashu_kvac methods to webassembly
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsValue;
use serde_wasm_bindgen::{from_value, to_value, Error};

use crate::{
    bulletproof::{BulletProof, InnerProductArgument}, kvac::{BalanceProof, BootstrapProof, IParamsProof, MacProof, ScriptEqualityProof}, models::{AmountAttribute, Coin, MintPrivateKey, MintPublicKey, RandomizedCoin, ScriptAttribute, MAC, ZKP}, secp::{GroupElement, Scalar}, transcript::CashuTranscript
};

#[wasm_bindgen]
impl MintPrivateKey {
    pub fn wasm_from_scalars(scalars: Vec<Scalar>) -> Result<Self, JsValue> {
        Self::from_scalars(&scalars).map_err(|e| JsValue::from_str(&format!("{}", e)))
    }

    pub fn wasm_to_scalars(&self) -> Vec<Scalar> {
        self.to_scalars()
    }
}

#[wasm_bindgen]
impl AmountAttribute {
    pub fn wasm_create_new(amount: u64, blinding_factor: Option<Vec<u8>>) -> Self {
        match blinding_factor {
            Some(blinding_factor) => Self::new(amount, Some(&blinding_factor)),
            None => Self::new(amount, None),
        }
    }

    pub fn wasm_commitment(&self) -> GroupElement {
        self.commitment()
    }

    pub fn wasm_tweak_amount(&mut self, amount: u64) -> () {
        let _ = self.tweak_amount(amount);
    }
}

#[wasm_bindgen]
impl ScriptAttribute {
    pub fn wasm_create_new(script: Vec<u8>, blinding_factor: Option<Vec<u8>>) -> Self {
        match blinding_factor {
            Some(blinding_factor) => Self::new(&script, Some(&blinding_factor)),
            None => Self::new(&script, None),
        }
    }

    pub fn wasm_commitment(&self) -> GroupElement {
        self.commitment()
    }
}

#[wasm_bindgen]
impl MAC {
    pub fn wasm_generate(
        mint_privkey: &MintPrivateKey,
        amount_commitment: GroupElement,
        script_commitment: Option<GroupElement>,
        tag: Option<Scalar>,
    ) -> Result<Self, JsValue> {
        Self::generate(
            mint_privkey,
            &amount_commitment,
            script_commitment.as_ref(),
            tag.as_ref(),
        )
        .map_err(|e| JsValue::from_str(&format!("{}", e)))
    }
}

#[wasm_bindgen]
impl Coin {
    pub fn wasm_create_new(
        amount_attribute: AmountAttribute,
        script_attribute: Option<ScriptAttribute>,
        mac: MAC,
    ) -> Self {
        Self::new(amount_attribute, script_attribute, mac)
    }
}

#[wasm_bindgen]
impl RandomizedCoin {
    pub fn wasm_from_coin(coin: &Coin, reveal_script: bool) -> Result<Self, JsValue> {
        Self::from_coin(coin, reveal_script).map_err(|e| JsValue::from_str(&format!("{}", e)))
    }
}

#[wasm_bindgen]
impl BootstrapProof {
    pub fn wasm_create(
        amount_attribute: &AmountAttribute, transcript: &mut CashuTranscript
    ) -> ZKP {
        BootstrapProof::create(amount_attribute, transcript)
    }

    pub fn wasm_verify(
        amount_commitment: &GroupElement,
        proof: ZKP,
        transcript: &mut CashuTranscript,
    ) -> bool {
        BootstrapProof::verify(amount_commitment, proof, transcript)
    }
}

#[wasm_bindgen]
impl MacProof {
    pub fn wasm_create(
        mint_publickey: &MintPublicKey,
        coin: &Coin,
        randomized_coin: &RandomizedCoin,
        transcript: &mut CashuTranscript,
    ) -> ZKP {
        MacProof::create(mint_publickey, coin, randomized_coin, transcript)
    }

    pub fn wasm_verify(
        mint_privkey: &MintPrivateKey,
        randomized_coin: &RandomizedCoin,
        script: Option<Vec<u8>>,
        proof: ZKP,
        transcript: &mut CashuTranscript,
    ) -> bool {
        match script {
            None => MacProof::verify(mint_privkey, randomized_coin, None, proof, transcript),
            Some(script) => MacProof::verify(mint_privkey, randomized_coin, Some(&script), proof, transcript)
        }
    }
}

#[wasm_bindgen]
impl IParamsProof {
    pub fn wasm_create(
        mint_privkey: &MintPrivateKey,
        mac: &MAC,
        amount_commitment: GroupElement,
        script_commitment: Option<GroupElement>,
        transcript: &mut CashuTranscript,
    ) -> ZKP {
        IParamsProof::create(mint_privkey, mac, &amount_commitment, script_commitment.as_ref(), transcript)
    }

    pub fn wasm_verify(
        mint_publickey: &MintPublicKey,
        coin: &Coin,
        proof: ZKP,
        transcript: &mut CashuTranscript,
    ) -> bool {
        IParamsProof::verify(mint_publickey, coin, proof, transcript)
    }
}

#[wasm_bindgen]
impl BalanceProof {
    pub fn wasm_create (
        inputs: Vec<AmountAttribute>,
        outputs: Vec<AmountAttribute>,
        transcript: &mut CashuTranscript,
    ) -> ZKP {
        BalanceProof::create(&inputs, &outputs, transcript)
    }

    pub fn wasm_verify(
        inputs: Vec<RandomizedCoin>,
        outputs: Vec<GroupElement>,
        delta_amount: i64,
        proof: ZKP,
        transcript: &mut CashuTranscript,
    ) -> bool {
        BalanceProof::verify(&inputs, &outputs, delta_amount, proof, transcript)
    }
}

#[wasm_bindgen]
pub struct OutputAttributesPair {
    amount_attribute: AmountAttribute,
    script_attribute: ScriptAttribute,
}

#[wasm_bindgen]
pub struct OutputCommitmentsPair {
    amount_commitment: GroupElement,
    script_commitment: GroupElement,
}

#[wasm_bindgen]
impl ScriptEqualityProof {
    pub fn wasm_create(
        inputs: Vec<Coin>,
        randomized_inputs: Vec<RandomizedCoin>,
        outputs: Vec<OutputAttributesPair>,
        transcript: &mut CashuTranscript,
    ) -> Result<ZKP, JsValue> {
        let outputs: Vec<(AmountAttribute, ScriptAttribute)> = outputs
            .into_iter()
            .map(|o| (o.amount_attribute, o.script_attribute))
            .collect();
        ScriptEqualityProof::create(&inputs, &randomized_inputs, &outputs, transcript)
            .map_err(|e| JsValue::from_str(&format!("{}", e)))
    }
    
    pub fn wasm_verify(
        randomized_inputs: Vec<RandomizedCoin>,
        outputs: Vec<OutputCommitmentsPair>,
        proof: ZKP,
        transcript: &mut CashuTranscript,
    ) -> bool {
        let outputs: Vec<(GroupElement, GroupElement)> = outputs
            .into_iter()
            .map(|o| (o.amount_commitment, o.script_commitment))
            .collect();
        ScriptEqualityProof::verify(&randomized_inputs, &outputs, proof, transcript)
    }
}

#[wasm_bindgen]
pub struct WasmInnerProductArgument {
    public_inputs: JsValue,
    tail_end_scalars: (Scalar, Scalar),
}

#[wasm_bindgen]
#[allow(non_snake_case)]
pub struct WasmBulletProof {
    A: GroupElement,
    S: GroupElement,
    T1: GroupElement,
    T2: GroupElement,
    t_x: Scalar,
    tau_x: Scalar,
    mu: Scalar,
    ipa: WasmInnerProductArgument,
}

#[wasm_bindgen]
impl WasmBulletProof {
    pub fn wasm_create(attributes: Vec<AmountAttribute>, transcript: &mut CashuTranscript) -> Self {
        let bulletproof = BulletProof::new(transcript, &attributes);
        let wasm_ipa = WasmInnerProductArgument {
            public_inputs: to_value(&bulletproof.ipa.public_inputs).expect("can always convert IPA public inputs to JsValue"),
            tail_end_scalars: bulletproof.ipa.tail_end_scalars,
        };
        WasmBulletProof { 
            A: bulletproof.A,
            S: bulletproof.S,
            T1: bulletproof.T1,
            T2: bulletproof.T2,
            t_x: bulletproof.t_x,
            tau_x: bulletproof.t_x,
            mu: bulletproof.mu,
            ipa: wasm_ipa
        }
    }
    
    pub fn wasm_verify(
        self,
        attribute_commitments: Vec<GroupElement>,
        transcript: &mut CashuTranscript
    ) -> bool {
        let ipa_public_inputs: Result<Vec<(GroupElement, GroupElement)>, Error> = from_value(self.ipa.public_inputs);
        let ipa_public_inputs = match ipa_public_inputs {
            Ok(ipa_public_inputs) => ipa_public_inputs,  // If the conversion is successful, return the public inputs
            Err(_) => return false, // If conversion fails, return false
        };
        let ipa = InnerProductArgument {
            public_inputs: ipa_public_inputs,
            tail_end_scalars: self.ipa.tail_end_scalars,
        };
        let bulletproof = BulletProof {
            A: self.A,
            S: self.S,
            T1: self.T1,
            T2: self.T2,
            t_x: self.t_x,
            tau_x: self.tau_x,
            mu: self.mu,
            ipa,
        };
        bulletproof.verify(transcript, &attribute_commitments)
    }
}