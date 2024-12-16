
use crate::models::{Statement, ZKP};
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