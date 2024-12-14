use crate::{generators::GENERATORS, secp::{GroupElement, Scalar}};
use bitcoin::hashes::sha256::Hash as Sha256Hash;
use bitcoin::hashes::Hash;

pub const RANGE_LIMIT: u64 = 32_u64;

pub struct MintPrivateKey {
    pub w: Scalar,
    pub w_: Scalar,
    pub x0: Scalar,
    pub x1: Scalar,
    pub ya: Scalar,
    pub ys: Scalar,

    // Public parameters
    pub cw: Option<GroupElement>,
    pub i: Option<GroupElement>
}

impl MintPrivateKey {

    pub fn from_scalars(scalars: [Scalar; 6]) -> Self {
        let [w, w_, x0, x1, ya, ys] = scalars;
        MintPrivateKey {
            w,
            w_,
            x0,
            x1,
            ya,
            ys,
            cw: None,
            i: None,
        }
    }

    pub fn to_scalars(&self) -> Vec<Scalar> {
        vec![self.w.clone(), self.w_.clone(), self.x0.clone(), self.x1.clone(), self.ya.clone(), self.ys.clone()]
    }

    pub fn pubkey(&mut self) -> Vec<GroupElement> {
        if !self.cw.is_some() {
            self.cw = Some(GENERATORS.w.clone()*&self.w + &(GENERATORS.w_.clone()*&self.w_));
        }
        if !self.i.is_some() {
            self.i = Some(
                GENERATORS.gz_mac.clone() - &(
                    GENERATORS.x0.clone()*&self.x0
                    + &(
                        GENERATORS.x1.clone()*&self.x1
                        + &(
                            GENERATORS.gz_attribute.clone()*&self.ya
                            + &(
                                GENERATORS.gz_script.clone()*&self.ys
                            )
                        ) 
                    ) 
                )
            );
        }
        vec![
            self.cw.as_ref().expect("Expected Cw").clone(),
            self.i.as_ref().expect("Expected I").clone(),
        ]
    }
}


pub struct ZKP {
    pub s: Vec<Scalar>,
    pub c: Scalar
}

pub struct ScriptAttribute {
    r: Scalar,
    s: Scalar,
    Ms: Option<GroupElement>,
}

/*
impl ScriptAttribute {
    pub fn new(script: &[u8], blinding_factor: Option<&[u8]>) -> Self {
        let s = Scalar::new(&Sha256Hash::hash(&script).to_byte_array());
        if let b_factor = Some(blinding_factor) {

        }
    }
}
*/