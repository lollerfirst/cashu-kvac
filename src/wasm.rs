//! Module used to bridge the interface of cashu_kvac methods to webassembly
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsValue;

use crate::{
    models::{AmountAttribute, Coin, MintPrivateKey, RandomizedCoin, ScriptAttribute, MAC},
    secp::{GroupElement, Scalar},
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
