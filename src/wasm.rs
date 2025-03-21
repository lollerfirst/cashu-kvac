//! Module used to bridge the interface of cashu_kvac methods to webassembly
use serde_wasm_bindgen::{from_value, to_value, Error};
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsValue;

use crate::{
    bulletproof::{BulletProof, InnerProductArgument},
    kvac::{BalanceProof, BootstrapProof, IParamsProof, MacProof, ScriptEqualityProof},
    models::{
        AmountAttribute, Coin, MintPrivateKey, MintPublicKey, RandomizedCoin, ScriptAttribute, MAC,
        ZKP,
    },
    secp::{GroupElement, Scalar},
    transcript::CashuTranscript,
};

#[wasm_bindgen]
impl Scalar {
    #[allow(non_snake_case)]
    pub fn wasmFromBytesBE(bytes: Vec<u8>) -> Self {
        Self::new(&bytes)
    }

    #[allow(non_snake_case)]
    pub fn wasmFromHex(hex: String) -> Result<Self, JsValue> {
        Self::try_from(hex.as_ref()).map_err(|e| JsValue::from_str(&format!("{}", e)))
    }

    #[allow(non_snake_case)]
    pub fn wasmFromUnsignedNumber(number: u64) -> Self {
        Self::from(number)
    }
}

#[wasm_bindgen]
impl GroupElement {
    #[allow(non_snake_case)]
    pub fn wasmFromBytesBE(bytes: Vec<u8>) -> Self {
        Self::new(&bytes)
    }

    #[allow(non_snake_case)]
    pub fn wasmFromHex(hex: String) -> Result<Self, JsValue> {
        Self::try_from(hex.as_ref()).map_err(|e| JsValue::from_str(&format!("{}", e)))
    }
}

#[wasm_bindgen]
impl MintPrivateKey {
    #[allow(non_snake_case)]
    pub fn wasmFromScalars(scalars: Vec<Scalar>) -> Result<Self, JsValue> {
        Self::from_scalars(&scalars).map_err(|e| JsValue::from_str(&format!("{}", e)))
    }

    #[allow(non_snake_case)]
    pub fn wasmToScalars(&self) -> Vec<Scalar> {
        self.to_scalars()
    }
}

#[wasm_bindgen]
impl AmountAttribute {
    #[allow(non_snake_case)]
    pub fn wasmCreateNew(amount: u64, blindingFactor: Option<Vec<u8>>) -> Self {
        match blindingFactor {
            Some(blinding_factor) => Self::new(amount, Some(&blinding_factor)),
            None => Self::new(amount, None),
        }
    }

    #[allow(non_snake_case)]
    pub fn wasmCommitment(&self) -> GroupElement {
        self.commitment()
    }

    #[allow(non_snake_case)]
    pub fn wasmTweakAmount(&mut self, amount: u64) {
        let _ = self.tweak_amount(amount);
    }
}

#[wasm_bindgen]
impl ScriptAttribute {
    #[allow(non_snake_case)]
    pub fn wasmCreateNew(script: Vec<u8>, blindingFactor: Option<Vec<u8>>) -> Self {
        match blindingFactor {
            Some(blinding_factor) => Self::new(&script, Some(&blinding_factor)),
            None => Self::new(&script, None),
        }
    }

    #[allow(non_snake_case)]
    pub fn wasmCommitment(&self) -> GroupElement {
        self.commitment()
    }
}

#[wasm_bindgen]
#[allow(non_snake_case)]
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
}

#[wasm_bindgen]
#[allow(non_snake_case)]
impl Coin {
    pub fn wasmCreateNew(
        amountAttribute: AmountAttribute,
        scriptAttribute: Option<ScriptAttribute>,
        mac: MAC,
    ) -> Self {
        Self::new(amountAttribute, scriptAttribute, mac)
    }
}

#[wasm_bindgen]
#[allow(non_snake_case)]
impl RandomizedCoin {
    pub fn wasmFromCoin(coin: &Coin, revealScript: bool) -> Result<Self, JsValue> {
        Self::from_coin(coin, revealScript).map_err(|e| JsValue::from_str(&format!("{}", e)))
    }
}

#[wasm_bindgen]
impl BootstrapProof {
    #[allow(non_snake_case)]
    pub fn wasmCreate(amountAttribute: &AmountAttribute, transcript: &mut CashuTranscript) -> ZKP {
        BootstrapProof::create(amountAttribute, transcript)
    }

    #[allow(non_snake_case)]
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
    #[allow(non_snake_case)]
    pub fn wasmCreate(
        mintPublickey: &MintPublicKey,
        coin: &Coin,
        randomizedCoin: &RandomizedCoin,
        transcript: &mut CashuTranscript,
    ) -> ZKP {
        MacProof::create(mintPublickey, coin, randomizedCoin, transcript)
    }

    #[allow(non_snake_case)]
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
#[allow(non_snake_case)]
impl IParamsProof {
    #[allow(non_snake_case)]
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

    #[allow(non_snake_case)]
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
    #[allow(non_snake_case)]
    pub fn wasmCreate(
        inputs: Vec<AmountAttribute>,
        outputs: Vec<AmountAttribute>,
        transcript: &mut CashuTranscript,
    ) -> ZKP {
        BalanceProof::create(&inputs, &outputs, transcript)
    }

    #[allow(non_snake_case)]
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
#[allow(non_snake_case)]
pub struct OutputAttributesPair {
    amountAttribute: AmountAttribute,
    scriptAttribute: ScriptAttribute,
}

#[wasm_bindgen]
#[allow(non_snake_case)]
pub struct OutputCommitmentsPair {
    amountCommitment: GroupElement,
    scriptCommitment: GroupElement,
}

#[wasm_bindgen]
impl ScriptEqualityProof {
    #[allow(non_snake_case)]
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

    #[allow(non_snake_case)]
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
#[allow(non_snake_case)]
pub struct WasmInnerProductArgument {
    publicInputs: JsValue,
    tailEndScalars: (Scalar, Scalar),
}

#[wasm_bindgen]
#[allow(non_snake_case)]
pub struct WasmBulletProof {
    A: GroupElement,
    S: GroupElement,
    T1: GroupElement,
    T2: GroupElement,
    tX: Scalar,
    tauX: Scalar,
    mu: Scalar,
    ipa: WasmInnerProductArgument,
}

#[wasm_bindgen]
impl WasmBulletProof {
    #[allow(non_snake_case)]
    pub fn wasmCreate(attributes: Vec<AmountAttribute>, transcript: &mut CashuTranscript) -> Self {
        let bulletproof = BulletProof::new(transcript, &attributes);
        let wasmIpa = WasmInnerProductArgument {
            publicInputs: to_value(&bulletproof.ipa.public_inputs)
                .expect("can always convert IPA public inputs to JsValue"),
            tailEndScalars: bulletproof.ipa.tail_end_scalars,
        };
        WasmBulletProof {
            A: bulletproof.A,
            S: bulletproof.S,
            T1: bulletproof.T1,
            T2: bulletproof.T2,
            tX: bulletproof.t_x,
            tauX: bulletproof.tau_x,
            mu: bulletproof.mu,
            ipa: wasmIpa,
        }
    }

    #[allow(non_snake_case)]
    pub fn wasmVerify(
        self,
        attributeCommitments: Vec<GroupElement>,
        transcript: &mut CashuTranscript,
    ) -> bool {
        let ipaPublicInputs: Result<Vec<(GroupElement, GroupElement)>, Error> =
            from_value(self.ipa.publicInputs);
        let ipaPublicInputs = match ipaPublicInputs {
            Ok(ipaPublicInputs) => ipaPublicInputs, // If the conversion is successful, return the public inputs
            Err(_) => return false,                 // If conversion fails, return false
        };
        let ipa = InnerProductArgument {
            public_inputs: ipaPublicInputs,
            tail_end_scalars: self.ipa.tailEndScalars,
        };
        let bulletproof = BulletProof {
            A: self.A,
            S: self.S,
            T1: self.T1,
            T2: self.T2,
            t_x: self.tX,
            tau_x: self.tauX,
            mu: self.mu,
            ipa,
        };
        bulletproof.verify(transcript, &attributeCommitments)
    }
}

#[wasm_bindgen]
#[allow(non_snake_case)]
impl CashuTranscript {
    pub fn wasmCreateNew() -> Self {
        Self::new()
    }
}
