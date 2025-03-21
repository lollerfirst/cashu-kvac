//! Module used to bridge the interface of cashu_kvac methods to webassembly
#![allow(non_snake_case)]
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsValue;

use crate::{
    bulletproof::BulletProof,
    kvac::{BalanceProof, BootstrapProof, IParamsProof, MacProof, ScriptEqualityProof},
    models::{
        AmountAttribute, Coin, MintPrivateKey, MintPublicKey, RandomizedCoin, ScriptAttribute, MAC,
        ZKP,
    },
    secp::{GroupElement, Scalar},
    transcript::CashuTranscript,
};

macro_rules! toJson {
    ($self_ref: ident) => {
        serde_json::to_string_pretty($self_ref).map_err(|e| JsValue::from_str(&format!("{}", e)))
    };
}

macro_rules! fromJson {
    ($json_str: expr) => {
        serde_json::from_str($json_str).map_err(|e| JsValue::from_str(&format!("{}", e)))
    };
}

#[wasm_bindgen]
impl Scalar {
    pub fn wasmFromBytesBE(bytes: Vec<u8>) -> Self {
        Self::new(&bytes)
    }

    pub fn wasmFromHex(hex: String) -> Result<Self, JsValue> {
        Self::try_from(hex.as_ref()).map_err(|e| JsValue::from_str(&format!("{}", e)))
    }

    pub fn wasmFromUnsignedNumber(number: u64) -> Self {
        Self::from(number)
    }

    pub fn wasmSerialize(&self) -> Vec<u8> {
        self.to_bytes()
    }

    pub fn wasmSerializeToHex(&self) -> String {
        self.into()
    }

    pub fn wasmCreateRandom() -> Self {
        Self::random()
    }
}

#[wasm_bindgen]
impl GroupElement {
    pub fn wasmFromBytesBE(bytes: Vec<u8>) -> Self {
        Self::new(&bytes)
    }

    pub fn wasmFromHex(hex: String) -> Result<Self, JsValue> {
        Self::try_from(hex.as_ref()).map_err(|e| JsValue::from_str(&format!("{}", e)))
    }

    pub fn wasmSerialize(&self) -> Vec<u8> {
        self.to_bytes()
    }

    pub fn wasmSerializeToHex(&self) -> String {
        self.into()
    }
}

#[wasm_bindgen]
impl MintPrivateKey {
    pub fn wasmFromScalars(scalars: Vec<Scalar>) -> Result<Self, JsValue> {
        Self::from_scalars(&scalars).map_err(|e| JsValue::from_str(&format!("{}", e)))
    }

    pub fn wasmToScalars(&self) -> Vec<Scalar> {
        self.to_scalars()
    }

    pub fn fromJson(json: String) -> Result<Self, JsValue> {
        let me: Self = fromJson!(json.as_ref())?;
        Ok(me)
    }
}

#[wasm_bindgen]
impl AmountAttribute {
    pub fn wasmCreateNew(amount: u64, blindingFactor: Option<Vec<u8>>) -> Self {
        match blindingFactor {
            Some(blinding_factor) => Self::new(amount, Some(&blinding_factor)),
            None => Self::new(amount, None),
        }
    }

    pub fn wasmCommitment(&self) -> GroupElement {
        self.commitment()
    }

    pub fn wasmTweakAmount(&mut self, amount: u64) {
        let _ = self.tweak_amount(amount);
    }

    pub fn toJson(&self) -> Result<String, JsValue> {
        toJson!(self)
    }

    pub fn fromJson(json: String) -> Result<Self, JsValue> {
        let me: Self = fromJson!(json.as_ref())?;
        Ok(me)
    }
}

#[wasm_bindgen]
impl ScriptAttribute {
    pub fn wasmCreateNew(script: Vec<u8>, blindingFactor: Option<Vec<u8>>) -> Self {
        match blindingFactor {
            Some(blinding_factor) => Self::new(&script, Some(&blinding_factor)),
            None => Self::new(&script, None),
        }
    }

    pub fn wasmCommitment(&self) -> GroupElement {
        self.commitment()
    }

    pub fn toJson(&self) -> Result<String, JsValue> {
        toJson!(self)
    }

    pub fn fromJson(json: String) -> Result<Self, JsValue> {
        let me: Self = fromJson!(json.as_ref())?;
        Ok(me)
    }
}

#[wasm_bindgen]

impl MAC {
    pub fn wasmGenerate(
        mintPrivkey: &MintPrivateKey,
        amountCommitment: GroupElement,
        scriptCommitment: Option<GroupElement>,
        tag: Option<Scalar>,
    ) -> Result<Self, JsValue> {
        Self::generate(
            mintPrivkey,
            &amountCommitment,
            scriptCommitment.as_ref(),
            tag.as_ref(),
        )
        .map_err(|e| JsValue::from_str(&format!("{}", e)))
    }

    pub fn toJson(&self) -> Result<String, JsValue> {
        toJson!(self)
    }

    pub fn fromJson(json: String) -> Result<Self, JsValue> {
        let me: Self = fromJson!(json.as_ref())?;
        Ok(me)
    }
}

#[wasm_bindgen]

impl Coin {
    pub fn wasmCreateNew(
        amountAttribute: AmountAttribute,
        scriptAttribute: Option<ScriptAttribute>,
        mac: MAC,
    ) -> Self {
        Self::new(amountAttribute, scriptAttribute, mac)
    }

    pub fn toJson(&self) -> Result<String, JsValue> {
        toJson!(self)
    }

    pub fn fromJson(json: String) -> Result<Self, JsValue> {
        let me: Self = fromJson!(json.as_ref())?;
        Ok(me)
    }
}

#[wasm_bindgen]

impl RandomizedCoin {
    pub fn wasmFromCoin(coin: &Coin, revealScript: bool) -> Result<Self, JsValue> {
        Self::from_coin(coin, revealScript).map_err(|e| JsValue::from_str(&format!("{}", e)))
    }

    pub fn toJson(&self) -> Result<String, JsValue> {
        toJson!(self)
    }

    pub fn fromJson(json: String) -> Result<Self, JsValue> {
        let me: Self = fromJson!(json.as_ref())?;
        Ok(me)
    }
}

#[wasm_bindgen]
impl BootstrapProof {
    pub fn wasmCreate(amountAttribute: &AmountAttribute, transcript: &mut CashuTranscript) -> ZKP {
        BootstrapProof::create(amountAttribute, transcript)
    }

    pub fn wasmVerify(
        amountCommitment: &GroupElement,
        proof: ZKP,
        transcript: &mut CashuTranscript,
    ) -> bool {
        BootstrapProof::verify(amountCommitment, proof, transcript)
    }
}

#[wasm_bindgen]
impl MacProof {
    pub fn wasmCreate(
        mintPublickey: &MintPublicKey,
        coin: &Coin,
        randomizedCoin: &RandomizedCoin,
        transcript: &mut CashuTranscript,
    ) -> ZKP {
        MacProof::create(mintPublickey, coin, randomizedCoin, transcript)
    }

    pub fn wasmVerify(
        mintPrivkey: &MintPrivateKey,
        randomizedCoin: &RandomizedCoin,
        script: Option<Vec<u8>>,
        proof: ZKP,
        transcript: &mut CashuTranscript,
    ) -> bool {
        match script {
            None => MacProof::verify(mintPrivkey, randomizedCoin, None, proof, transcript),
            Some(script) => MacProof::verify(
                mintPrivkey,
                randomizedCoin,
                Some(&script),
                proof,
                transcript,
            ),
        }
    }
}

#[wasm_bindgen]

impl IParamsProof {
    pub fn wasmCreate(
        mintPrivkey: &MintPrivateKey,
        mac: &MAC,
        amountCommitment: GroupElement,
        scriptCommitment: Option<GroupElement>,
        transcript: &mut CashuTranscript,
    ) -> ZKP {
        IParamsProof::create(
            mintPrivkey,
            mac,
            &amountCommitment,
            scriptCommitment.as_ref(),
            transcript,
        )
    }

    pub fn wasmVerify(
        mintPublickey: &MintPublicKey,
        coin: &Coin,
        proof: ZKP,
        transcript: &mut CashuTranscript,
    ) -> bool {
        IParamsProof::verify(mintPublickey, coin, proof, transcript)
    }
}

#[wasm_bindgen]
impl BalanceProof {
    pub fn wasmCreate(
        inputs: Vec<AmountAttribute>,
        outputs: Vec<AmountAttribute>,
        transcript: &mut CashuTranscript,
    ) -> ZKP {
        BalanceProof::create(&inputs, &outputs, transcript)
    }

    pub fn wasmVerify(
        inputs: Vec<RandomizedCoin>,
        outputs: Vec<GroupElement>,
        deltaAmount: i64,
        proof: ZKP,
        transcript: &mut CashuTranscript,
    ) -> bool {
        BalanceProof::verify(&inputs, &outputs, deltaAmount, proof, transcript)
    }
}

#[wasm_bindgen]
pub struct OutputAttributesPair {
    amountAttribute: AmountAttribute,
    scriptAttribute: ScriptAttribute,
}

#[wasm_bindgen]
pub struct OutputCommitmentsPair {
    amountCommitment: GroupElement,
    scriptCommitment: GroupElement,
}

#[wasm_bindgen]
impl ScriptEqualityProof {
    pub fn wasmCreate(
        inputs: Vec<Coin>,
        randomizedInputs: Vec<RandomizedCoin>,
        outputs: Vec<OutputAttributesPair>,
        transcript: &mut CashuTranscript,
    ) -> Result<ZKP, JsValue> {
        let outputs: Vec<(AmountAttribute, ScriptAttribute)> = outputs
            .into_iter()
            .map(|o| (o.amountAttribute, o.scriptAttribute))
            .collect();
        ScriptEqualityProof::create(&inputs, &randomizedInputs, &outputs, transcript)
            .map_err(|e| JsValue::from_str(&format!("{}", e)))
    }

    pub fn wasmVerify(
        randomizedInputs: Vec<RandomizedCoin>,
        outputs: Vec<OutputCommitmentsPair>,
        proof: ZKP,
        transcript: &mut CashuTranscript,
    ) -> bool {
        let outputs: Vec<(GroupElement, GroupElement)> = outputs
            .into_iter()
            .map(|o| (o.amountCommitment, o.scriptCommitment))
            .collect();
        ScriptEqualityProof::verify(&randomizedInputs, &outputs, proof, transcript)
    }
}

#[wasm_bindgen]
impl BulletProof {
    pub fn wasmCreate(attributes: Vec<AmountAttribute>, transcript: &mut CashuTranscript) -> Self {
        Self::new(transcript, &attributes)
    }

    pub fn wasmVerify(
        self,
        amount_commiments: Vec<GroupElement>,
        transcript: &mut CashuTranscript,
    ) -> bool {
        self.verify(transcript, &amount_commiments)
    }

    pub fn toJson(&self) -> Result<String, JsValue> {
        toJson!(self)
    }

    pub fn fromJson(json: String) -> Result<Self, JsValue> {
        let me: Self = fromJson!(json.as_ref())?;
        Ok(me)
    }
}

#[wasm_bindgen]
impl ZKP {
    pub fn toJson(&self) -> Result<String, JsValue> {
        toJson!(self)
    }

    pub fn fromJson(json: String) -> Result<Self, JsValue> {
        let me: Self = fromJson!(json.as_ref())?;
        Ok(me)
    }
}

#[wasm_bindgen]
impl CashuTranscript {
    pub fn wasmCreateNew() -> Self {
        Self::new()
    }
}
