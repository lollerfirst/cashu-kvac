
use crate::generators::{hash_to_curve, GENERATORS};
use crate::models::{AmountAttribute, Coin, Equation, MintPrivateKey, Statement, ZKP};
use crate::transcript::CashuTranscript;
use crate::secp::{GroupElement, Scalar, GROUP_ELEMENT_ZERO};

pub struct SchnorrProver<'a> {
    random_terms: Vec<Scalar>,
    secrets: Vec<Scalar>,
    transcript: &'a mut CashuTranscript,
}

impl<'a> SchnorrProver<'a> {
    pub fn new(
        transcript: &'a mut CashuTranscript,
        secrets: Vec<Scalar>,
    ) -> Self {
        SchnorrProver {
            random_terms: vec![Scalar::random(); secrets.len()],
            secrets,
            transcript,                        
        }
    }

    #[allow(non_snake_case)]
    pub fn add_statement(&mut self, statement: Statement) {
        // Append proof-specific domain separator to the transcript
        self.transcript.domain_sep(&statement.domain_separator);

        for equation in statement.equations.into_iter() {

            let mut R = GroupElement::new(&GROUP_ELEMENT_ZERO);
            let V = equation.lhs;

            for row in equation.rhs.into_iter() {
                for (k, P) in self.random_terms.iter().zip(row.into_iter())  {
                   R = R + (P * k).as_ref();
                }
            }

            self.transcript.append_element(b"R_", &R);
            self.transcript.append_element(b"V_", &V);
        }
    }

    #[allow(non_snake_case)]
    pub fn prove(self) -> ZKP {
        // Draw a challenge from the running transcript
        let c = self.transcript.get_challenge(b"chall_");

        // Create responses to the challenge
        let mut responses: Vec<Scalar> = vec![];
        for (k, s) in self.random_terms.into_iter().zip(self.secrets.into_iter()) {
            responses.push(
                k + (s * c.as_ref()).as_ref()
            );
        }

        ZKP { s: responses, c }
    }
}

pub struct SchnorrVerifier<'a> {
    responses: Vec<Scalar>,
    challenge: Scalar,
    transcript: &'a mut CashuTranscript,
}

impl<'a> SchnorrVerifier<'a> {
    pub fn new(
        transcript: &'a mut CashuTranscript,
        proof: ZKP,
    ) -> Self {
        SchnorrVerifier {
            responses: proof.s,
            challenge: proof.c,
            transcript,
        }
    }

    #[allow(non_snake_case)]
    pub fn add_statement(
        &mut self,
        statement: Statement
    ) {
        // Append proof-specific domain separator to the transcript
        self.transcript.domain_sep(&statement.domain_separator);

        for equation in statement.equations.into_iter() {

            let mut R = GroupElement::new(&GROUP_ELEMENT_ZERO);
            let V = equation.lhs;

            for row in equation.rhs.into_iter() {
                for (s, P) in self.responses.iter().zip(row.into_iter())  {
                   R = R + (P * s).as_ref();
                }
            }
            R = R - (V.clone() * self.challenge.as_ref()).as_ref();

            self.transcript.append_element(b"R_", &R);
            self.transcript.append_element(b"V_", &V);
        }
    }
}

pub struct BootstrapStatement {}

impl BootstrapStatement {
    pub fn new(amount_attribute: &mut AmountAttribute) -> Statement {
        Statement {
            domain_separator: b"Bootstrap_Statement_",
            equations: vec![
                Equation {          // Ma = r*G_blind
                    lhs: amount_attribute.commitment(),
                    rhs: vec![vec![GENERATORS.G_blind.clone()]] 
                }
            ]
        }
    }
}

pub struct IParamsStatement;

impl IParamsStatement {
    #[allow(non_snake_case)]
    pub fn new(mint_privkey: &mut MintPrivateKey, coin: &mut Coin) -> Statement {
        let O = GroupElement::new(&GROUP_ELEMENT_ZERO);
        let t_tag_bytes: [u8; 32] = coin.mac.t.as_ref().into();
        let t = coin.mac.t.as_ref();
        let U = hash_to_curve(&t_tag_bytes).expect("Couldn't get map MAC tag to GroupElement");
        let V = coin.mac.V.clone();
        let (Cw, I) = mint_privkey.pubkey();
        let Ma = coin.amount_attribute.commitment();
        let mut Ms = O.clone();
        if let Some(scr_attr) = &mut coin.script_attribute {
            Ms = scr_attr.commitment();
        }
        Statement {
            domain_separator: b"Iparams_Statement_",
            equations: vec![
                Equation {          // Cw = w*W  + w_*W_
                    lhs: Cw,
                    rhs: vec![vec![GENERATORS.W.clone()]]
                },
                Equation {          // I = Gz_mac - x0*X0 - x1*X1 - ya*Gz_attribute - ys*Gz_script
                    lhs: I - &GENERATORS.Gz_mac,
                    rhs: vec![vec![
                        O.clone(),
                        O.clone(),
                        -GENERATORS.X0.clone(),
                        -GENERATORS.X1.clone(),
                        -GENERATORS.Gz_attribute.clone(),
                        -GENERATORS.Gz_script.clone(),
                    ]]
                },
                Equation {         // V = w*W + x0*U + x1*t*U + ya*Ma + ys*Ms
                    lhs: V,
                    rhs: vec![vec![
                        GENERATORS.W.clone(),
                        O,
                        U.clone(),
                        U * t.as_ref(),
                        Ma,
                        Ms,
                    ]]
                }
            ]
        }
    }
}