use crate::{errors::Error, generators::{hash_to_curve, GENERATORS}, secp::{GroupElement, Scalar, GROUP_ELEMENT_ZERO}};
use bitcoin::hashes::sha256::Hash as Sha256Hash;
use bitcoin::hashes::Hash;

pub const RANGE_LIMIT: u64 = std::u32::MAX as u64;

#[allow(non_snake_case)]
pub struct MintPrivateKey {
    pub w: Scalar,
    pub w_: Scalar,
    pub x0: Scalar,
    pub x1: Scalar,
    pub ya: Scalar,
    pub ys: Scalar,

    // Public parameters
    pub Cw: Option<GroupElement>,
    pub I: Option<GroupElement>
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
            Cw: None,
            I: None,
        }
    }

    pub fn to_scalars(&self) -> Vec<Scalar> {
        vec![self.w.clone(), self.w_.clone(), self.x0.clone(), self.x1.clone(), self.ya.clone(), self.ys.clone()]
    }

    pub fn pubkey(&mut self) -> Vec<GroupElement> {
        if !self.Cw.is_some() {
            self.Cw = Some(GENERATORS.W.clone()*&self.w + &(GENERATORS.W_.clone()*&self.w_));
        }
        if !self.I.is_some() {
            self.I = Some(
                GENERATORS.Gz_mac.clone() - &(
                    GENERATORS.X0.clone()*&self.x0
                    + &(
                        GENERATORS.X1.clone()*&self.x1
                        + &(
                            GENERATORS.Gz_attribute.clone()*&self.ya
                            + &(
                                GENERATORS.Gz_script.clone()*&self.ys
                            )
                        ) 
                    ) 
                )
            );
        }
        vec![
            self.Cw.as_ref().expect("Expected Cw").clone(),
            self.I.as_ref().expect("Expected I").clone(),
        ]
    }
}


pub struct ZKP {
    pub s: Vec<Scalar>,
    pub c: Scalar
}

#[allow(non_snake_case)]
pub struct ScriptAttribute {
    pub r: Scalar,
    pub s: Scalar,
    Ms: Option<GroupElement>,
}


impl ScriptAttribute {
    pub fn new(script: &[u8], blinding_factor: Option<&[u8; 32]>) -> Self {
        let s = Scalar::new(&Sha256Hash::hash(&script).to_byte_array());
        if let Some(b_factor) = blinding_factor {
            let r = Scalar::new(b_factor);

            ScriptAttribute { r: r, s: s, Ms: None }
        } else {
            let r = Scalar::random();

            ScriptAttribute { r: r, s: s, Ms: None }
        }
    }

    pub fn commitment(&mut self) -> GroupElement {
        if !self.Ms.is_some() {
            self.Ms = Some(
                GENERATORS.G_script.clone() * &self.s + &(
                    GENERATORS.G_blind.clone() * &self.r
                )
            )
        }
        self.Ms.as_ref().expect("Couldn't get ScriptAttribute Commitment").clone()
    }
}

#[allow(non_snake_case)]
pub struct AmountAttribute {
    pub a: Scalar,
    pub r: Scalar,
    Ma: Option<GroupElement>,
}

impl AmountAttribute {
    pub fn new(amount: u64, blinding_factor: Option<&[u8; 32]>) -> Self {
        let a = Scalar::from(amount);
        if let Some(b_factor) = blinding_factor {
            let r = Scalar::new(b_factor);

            AmountAttribute { r: r, a: a, Ma: None }
        } else {
            let r = Scalar::random();

            AmountAttribute { r: r, a: a, Ma: None }
        }
    }

    pub fn commitment(&mut self) -> GroupElement{
        if !self.Ma.is_some() {
            self.Ma = Some(
                GENERATORS.G_amount.clone() * &self.a + &(
                    GENERATORS.G_blind.clone() * &self.r
                )
            )
        }
        self.Ma.as_ref().expect("Couldn't get ScriptAttribute Commitment").clone()
    }
}

#[allow(non_snake_case)]
pub struct MAC {
    pub t: Scalar,
    pub V: GroupElement,
}

impl MAC {
    #[allow(non_snake_case)]
    pub fn generate(
        privkey: &MintPrivateKey,
        amount_commitment: &GroupElement,
        script_commitment: Option<&GroupElement>,
        t_tag: Option<&Scalar>,
    ) -> Result<Self, Error> {
        let t: Scalar;
        if let Some(t_tag_some) = t_tag {
            t = t_tag_some.clone();
        } else {
            t = Scalar::random();
        }
        let t_bytes: [u8; 32] = t.clone().into();
        let U = hash_to_curve(&t_bytes)?;
        let Ma = amount_commitment.clone();
        let Ms: GroupElement;
        if let Some(com) = script_commitment {
            Ms = com.clone();
        } else {
            Ms = GroupElement::new(&GROUP_ELEMENT_ZERO);
        }
        let V = 
            GENERATORS.W.clone() * &privkey.w + &(
                U.clone() * &privkey.x0 + &(
                    U.clone() * &(t.clone() * &privkey.x1) + &(
                        Ma * &(privkey.ya) + &(
                            Ms * &(privkey.ys)
                        )
                    )
                )
            );
        Ok(MAC { t, V })
    }
}