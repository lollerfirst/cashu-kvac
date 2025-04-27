//! Module used to bridge the interface of cashu_kvac methods to webassembly
#![allow(non_snake_case)]
use serde_wasm_bindgen::{from_value, to_value};
use wasm_bindgen::JsValue;
use wasm_bindgen::{prelude::wasm_bindgen, JsError};

use crate::generators::hash_to_curve;
use crate::recovery::recover_amounts;
use crate::{
    bulletproof::BulletProof,
    kvac::{BalanceProof, BootstrapProof, IssuanceProof, MacProof, ScriptEqualityProof},
    models::{
        AmountAttribute, Coin, MintPrivateKey, MintPublicKey, RandomizedCoin, ScriptAttribute, MAC,
        ZKP,
    },
    secp::{GroupElement, Scalar},
    transcript::CashuTranscript,
};

macro_rules! json {
    ($name:ident) => {
        #[wasm_bindgen]
        impl $name {
            pub fn toJSON(&self) -> JsValue {
                to_value(&self).unwrap()
            }

            pub fn fromJSON(value: JsValue) -> Result<Self, JsError> {
                let me: Self = from_value(value).map_err(|e| JsError::new(&format!("{}", e)))?;
                Ok(me)
            }
        }
    };
}

json!(MintPrivateKey);
json!(Scalar);
json!(GroupElement);
json!(AmountAttribute);
json!(ScriptAttribute);
json!(MAC);
json!(Coin);
json!(RandomizedCoin);
json!(ZKP);
json!(BulletProof);
json!(MintPublicKey);

#[wasm_bindgen]
impl Scalar {
    pub fn wasmFromBytesBE(bytes: Vec<u8>) -> JsValue {
        Self::new(&bytes).toJSON()
    }

    pub fn wasmCreateRandom() -> JsValue {
        Self::random().toJSON()
    }
}

#[wasm_bindgen]
impl GroupElement {
    pub fn wasmFromBytesBE(bytes: Vec<u8>) -> JsValue {
        Self::new(&bytes).toJSON()
    }
}

#[wasm_bindgen]
impl AmountAttribute {
    pub fn wasmCreateNew(amount: u64, blindingFactor: Option<Vec<u8>>) -> JsValue {
        match blindingFactor {
            Some(blinding_factor) => Self::new(amount, Some(&blinding_factor)).toJSON(),
            None => Self::new(amount, None).toJSON(),
        }
    }

    pub fn wasmCommitment(amountAttr: JsValue) -> Result<JsValue, JsError> {
        let amountAttr = AmountAttribute::fromJSON(amountAttr)?;
        Ok(amountAttr.commitment().toJSON())
    }

    pub fn wasmTweakAmount(amountAttr: JsValue, amount: u64) -> Result<JsValue, JsError> {
        let mut amountAttr = AmountAttribute::fromJSON(amountAttr)?;
        amountAttr.tweak_amount(amount);
        Ok(amountAttr.toJSON())
    }
}

#[wasm_bindgen]
impl ScriptAttribute {
    pub fn wasmCreateNew(script: Vec<u8>, blindingFactor: Option<Vec<u8>>) -> JsValue {
        match blindingFactor {
            Some(blinding_factor) => Self::new(&script, Some(&blinding_factor)).toJSON(),
            None => Self::new(&script, None).toJSON(),
        }
    }

    pub fn wasmCommitment(scriptAttr: JsValue) -> Result<JsValue, JsError> {
        let scriptAttr = ScriptAttribute::fromJSON(scriptAttr)?;
        Ok(scriptAttr.commitment().toJSON())
    }
}

#[wasm_bindgen]
impl Coin {
    pub fn wasmCreateNew(
        amountAttribute: JsValue,
        scriptAttribute: JsValue,
        mac: JsValue,
    ) -> Result<JsValue, JsError> {
        let amountAttribute: AmountAttribute = AmountAttribute::fromJSON(amountAttribute)?;
        let scriptAttribute: Option<ScriptAttribute> =
            from_value(scriptAttribute).map_err(|e| JsError::new(&format!("{}", e)))?;
        let mac: MAC = MAC::fromJSON(mac)?;
        Ok(Self::new(amountAttribute, scriptAttribute, mac).toJSON())
    }
}

#[wasm_bindgen]
impl RandomizedCoin {
    pub fn wasmFromCoin(coin: JsValue, revealScript: bool) -> Result<JsValue, JsError> {
        let coin: Coin = Coin::fromJSON(coin)?;
        Ok(Self::from_coin(&coin, revealScript).unwrap().toJSON())
    }
}

#[wasm_bindgen]
impl BootstrapProof {
    pub fn wasmCreate(
        amountAttribute: JsValue,
        transcript: &mut CashuTranscript,
    ) -> Result<JsValue, JsError> {
        let amountAttr: AmountAttribute = AmountAttribute::fromJSON(amountAttribute)?;
        Ok(BootstrapProof::create(&amountAttr, transcript).toJSON())
    }

    pub fn wasmVerify(
        amountCommitment: JsValue,
        proof: JsValue,
        transcript: &mut CashuTranscript,
    ) -> Result<bool, JsError> {
        let amountComm: GroupElement = GroupElement::fromJSON(amountCommitment)?;
        let proof: ZKP = ZKP::fromJSON(proof)?;
        Ok(BootstrapProof::verify(&amountComm, proof, transcript))
    }
}

#[wasm_bindgen]
impl MacProof {
    pub fn wasmCreate(
        mintPublickey: JsValue,
        coin: JsValue,
        randomizedCoin: JsValue,
        transcript: &mut CashuTranscript,
    ) -> Result<JsValue, JsError> {
        let mintPubkey: MintPublicKey = MintPublicKey::fromJSON(mintPublickey)?;
        let coin: Coin = Coin::fromJSON(coin)?;
        let randomizedCoin: RandomizedCoin = RandomizedCoin::fromJSON(randomizedCoin)?;
        Ok(MacProof::create(&mintPubkey, &coin, &randomizedCoin, transcript).toJSON())
    }

    pub fn wasmVerify(
        mintPrivkey: JsValue,
        randomizedCoin: JsValue,
        script: Option<Vec<u8>>,
        proof: JsValue,
        transcript: &mut CashuTranscript,
    ) -> Result<bool, JsError> {
        let mintPrivkey: MintPrivateKey = MintPrivateKey::fromJSON(mintPrivkey)?;
        let randomizedCoin: RandomizedCoin = RandomizedCoin::fromJSON(randomizedCoin)?;
        let proof: ZKP = ZKP::fromJSON(proof)?;
        match script {
            None => Ok(MacProof::verify(
                &mintPrivkey,
                &randomizedCoin,
                None,
                proof,
                transcript,
            )),
            Some(script) => Ok(MacProof::verify(
                &mintPrivkey,
                &randomizedCoin,
                Some(&script),
                proof,
                transcript,
            )),
        }
    }
}

#[wasm_bindgen]
impl IssuanceProof {
    pub fn wasmCreate(
        mintPrivkey: JsValue,
        mac: JsValue,
        amountCommitment: JsValue,
        scriptCommitment: JsValue,
    ) -> Result<JsValue, JsError> {
        let mintPrivkey: MintPrivateKey = MintPrivateKey::fromJSON(mintPrivkey)?;
        let mac: MAC = MAC::fromJSON(mac)?;
        let amountCommitment: GroupElement = GroupElement::fromJSON(amountCommitment)?;
        let scriptCommitment: Option<GroupElement> =
            from_value(scriptCommitment).map_err(|e| JsError::new(&format!("{}", e)))?;
        Ok(IssuanceProof::create(
            &mintPrivkey,
            &mac,
            &amountCommitment,
            scriptCommitment.as_ref(),
        )
        .toJSON())
    }

    pub fn wasmVerify(
        mintPublickey: JsValue,
        coin: JsValue,
        proof: JsValue,
    ) -> Result<bool, JsError> {
        let mintPublickey: MintPublicKey = MintPublicKey::fromJSON(mintPublickey)?;
        let coin: Coin = Coin::fromJSON(coin)?;
        let proof: ZKP = ZKP::fromJSON(proof)?;
        Ok(IssuanceProof::verify(&mintPublickey, &coin, proof))
    }
}

#[wasm_bindgen]
impl BalanceProof {
    pub fn wasmCreate(
        inputs: JsValue,
        outputs: JsValue,
        transcript: &mut CashuTranscript,
    ) -> Result<JsValue, JsError> {
        let inputs: Vec<AmountAttribute> =
            from_value(inputs).map_err(|e| JsError::new(&format!("{}", e)))?;
        let outputs: Vec<AmountAttribute> =
            from_value(outputs).map_err(|e| JsError::new(&format!("{}", e)))?;
        Ok(BalanceProof::create(&inputs, &outputs, transcript).toJSON())
    }

    pub fn wasmVerify(
        inputs: JsValue,
        outputs: JsValue,
        deltaAmount: i64,
        proof: JsValue,
        transcript: &mut CashuTranscript,
    ) -> Result<bool, JsError> {
        let inputs: Vec<RandomizedCoin> =
            from_value(inputs).map_err(|e| JsError::new(&format!("{}", e)))?;
        let outputs: Vec<GroupElement> =
            from_value(outputs).map_err(|e| JsError::new(&format!("{}", e)))?;
        let proof: ZKP = ZKP::fromJSON(proof)?;
        Ok(BalanceProof::verify(
            &inputs,
            &outputs,
            deltaAmount,
            proof,
            transcript,
        ))
    }
}

#[wasm_bindgen]
impl ScriptEqualityProof {
    pub fn wasmCreate(
        inputs: JsValue,           //Vec<Coin>,
        randomizedInputs: JsValue, //Vec<RandomizedCoin>,
        outputs: JsValue,          //Vec<(AmountAttribute, ScriptAttribute)>,
        transcript: &mut CashuTranscript,
    ) -> Result<JsValue, JsError> {
        let outputs: Vec<(AmountAttribute, ScriptAttribute)> =
            from_value(outputs).map_err(|e| JsError::new(&format!("{}", e)))?;
        let inputs: Vec<Coin> = from_value(inputs).map_err(|e| JsError::new(&format!("{}", e)))?;
        let randomizedInputs: Vec<RandomizedCoin> =
            from_value(randomizedInputs).map_err(|e| JsError::new(&format!("{}", e)))?;
        Ok(
            ScriptEqualityProof::create(&inputs, &randomizedInputs, &outputs, transcript)
                .unwrap()
                .toJSON(),
        )
    }

    pub fn wasmVerify(
        randomizedInputs: JsValue,
        outputs: JsValue, //Vec<(GroupElement, GroupElement)>,
        proof: JsValue,
        transcript: &mut CashuTranscript,
    ) -> Result<bool, JsError> {
        let outputs: Vec<(GroupElement, GroupElement)> =
            from_value(outputs).map_err(|e| JsError::new(&format!("{}", e)))?;
        let randomizedInputs: Vec<RandomizedCoin> =
            from_value(randomizedInputs).map_err(|e| JsError::new(&format!("{}", e)))?;
        let proof: ZKP = ZKP::fromJSON(proof)?;
        Ok(ScriptEqualityProof::verify(
            &randomizedInputs,
            &outputs,
            proof,
            transcript,
        ))
    }
}

#[wasm_bindgen]
impl BulletProof {
    pub fn wasmCreate(
        attributes: JsValue,
        transcript: &mut CashuTranscript,
    ) -> Result<JsValue, JsError> {
        let attributes: Vec<AmountAttribute> =
            from_value(attributes).map_err(|e| JsError::new(&format!("{}", e)))?;
        Ok(Self::new(transcript, &attributes).toJSON())
    }

    pub fn wasmVerify(
        amount_commiments: JsValue,
        proof: JsValue,
        transcript: &mut CashuTranscript,
    ) -> Result<bool, JsError> {
        let amountComm: Vec<GroupElement> =
            from_value(amount_commiments).map_err(|e| JsError::new(&format!("{}", e)))?;
        let proof = BulletProof::fromJSON(proof)?;
        Ok(proof.verify(transcript, &amountComm))
    }
}

#[wasm_bindgen]
impl CashuTranscript {
    pub fn wasmCreateNew() -> Self {
        Self::new()
    }
}

#[wasm_bindgen]
pub fn wasmHashToG(hex: String) -> Result<JsValue, JsError> {
    let bytes = hex::decode(hex).map_err(|e| JsError::new(&format!("{}", e)))?;
    let ge = hash_to_curve(&bytes).expect("can map to GroupElement");
    Ok(ge.toJSON())
}

#[wasm_bindgen]
pub fn wasmRecoverAmounts(
    amount_commitments: JsValue,
    blinding_factors: JsValue,
    upper_bound: u64,
) -> Result<JsValue, JsError> {
    let amount_commitments: Vec<GroupElement> = from_value(amount_commitments)?;
    let blinding_factors: Vec<Scalar> = from_value(blinding_factors)?;
    let recovered_amounts = recover_amounts(&amount_commitments, &blinding_factors, upper_bound);
    Ok(to_value(&recovered_amounts)?)
}
