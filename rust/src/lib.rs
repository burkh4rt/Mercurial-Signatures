extern crate core;

use core::bn254::{big, ecp, ecp2, pair, rom};
use core::rand;

#[allow(non_snake_case, non_camel_case_types)]
pub struct MercurialSignatureScheme {
    ell: usize,       // length of keys & messages
    P: ecp::ECP,      // generator for the first group
    Phat: ecp2::ECP2, // generator for the paired group
    r: big::BIG,      // order of the isomorphic paired groups
}

#[allow(non_snake_case, non_camel_case_types)]
pub struct signature {
    // a mercurial signature
    Z: ecp::ECP,
    Y: ecp::ECP,
    Yhat: ecp2::ECP2,
}

#[allow(non_snake_case, non_camel_case_types)]
pub fn prepare_rng() -> core::rand::RAND {
    // sets up a random number generator
    let mut raw: [u8; 100] = [0; 100];
    let mut rng = rand::RAND::new();
    rng.clean();
    for i in 0..100 {
        raw[i] = i as u8
    }
    rng.seed(100, &raw);
    return rng;
}

#[allow(non_snake_case, non_camel_case_types)]
impl MercurialSignatureScheme {
    pub fn new(el: usize) -> MercurialSignatureScheme {
        MercurialSignatureScheme {
            ell: el,
            P: ecp::ECP::generator(),
            Phat: ecp2::ECP2::generator(),
            r: big::BIG::new_ints(&rom::CURVE_ORDER),
        }
    }

    pub fn randomMessage(&self, rng: &mut rand::RAND) -> Vec<ecp::ECP> {
        let mut M: Vec<ecp::ECP> = Vec::with_capacity(self.ell);
        for _ in 0..(self.ell as u64) {
            let mut Mj = ecp::ECP::new();
            Mj.copy(&self.P);
            let rand = big::BIG::randomnum(&self.r, rng);
            Mj = Mj.mul(&rand);
            M.push(Mj);
        }
        return M;
    }

    pub fn randomZp(&self, rng: &mut rand::RAND) -> big::BIG {
        let rho = big::BIG::randomnum(&self.r, rng);
        return rho;
    }

    pub fn KeyGen(&self, rng: &mut rand::RAND) -> (Vec<big::BIG>, Vec<ecp2::ECP2>) {
        // generates secret key sk, public key pk pair
        let mut sk: Vec<big::BIG> = Vec::with_capacity(self.ell);
        let mut pk: Vec<ecp2::ECP2> = Vec::with_capacity(self.ell);
        for _ in 0..(self.ell as u64) {
            let x = big::BIG::randomnum(&self.r, rng);
            let mut w = ecp2::ECP2::new();
            w.copy(&self.Phat);
            sk.push(x);
            pk.push(ecp2::ECP2::mul(&w, &x));
        }
        return (sk, pk);
    }

    pub fn Sign(&self, sk: &Vec<big::BIG>, M: &Vec<ecp::ECP>, rng: &mut rand::RAND) -> signature {
        // signs a message M using secret key sk
        let y = big::BIG::randomnum(&self.r, rng);
        let mut y_inv = big::BIG::new_copy(&y);
        big::BIG::invmodp(&mut y_inv, &self.r);
        let mut Z = M[0].mul(&sk[0]);
        for i in 1..self.ell {
            Z.add(&(M[i].mul(&sk[i])));
        }
        Z = Z.mul(&y);
        let Y = (&self.P).mul(&y_inv);
        let Yhat = (&self.Phat).mul(&y_inv);
        let sigma = signature {
            Z: Z,
            Y: Y,
            Yhat: Yhat,
        };
        return sigma;
    }

    pub fn Verify(&self, pk: &Vec<ecp2::ECP2>, M: &Vec<ecp::ECP>, sigma: &signature) -> bool {
        // verfies that the signature sigma corresponds to public key pk
        // and message M
        let Z = &sigma.Z;
        let Y = &sigma.Y;
        let Yhat = &sigma.Yhat;
        let mut q1 = pair::fexp(&pair::ate(&pk[0], &M[0]));
        for i in 1..self.ell {
            q1.mul(&pair::fexp(&pair::ate(&pk[i], &M[i])));
        }
        let q2 = pair::fexp(&pair::ate(&Yhat, &Z));
        let q3 = pair::fexp(&pair::ate(&self.Phat, &Y));
        let q4 = pair::fexp(&pair::ate(&Yhat, &self.P));
        return q1.equals(&q2) && q3.equals(&q4);
    }

    pub fn ConvertSK(&self, sk: Vec<big::BIG>, rho: &big::BIG) -> Vec<big::BIG> {
        // converts sk with randomness rho
        let mut new_sk = sk;
        for i in 0..self.ell {
            new_sk[i] = big::BIG::modmul(&new_sk[i], &rho, &self.r);
        }
        return new_sk;
    }

    pub fn ConvertPK(&self, pk: Vec<ecp2::ECP2>, rho: &big::BIG) -> Vec<ecp2::ECP2> {
        // converts pk with randomness rho
        let mut new_pk = pk;
        for i in 0..self.ell {
            new_pk[i] = ecp2::ECP2::mul(&new_pk[i], &rho);
        }
        return new_pk;
    }

    pub fn ConvertSignature(
        &self,
        sigma: signature,
        rho: &big::BIG,
        rng: &mut rand::RAND,
    ) -> signature {
        // converts sigma with randomness rho
        let mut new_sigma = sigma;
        let psi = big::BIG::randomnum(&self.r, rng);
        let mut psi_inv = big::BIG::new_copy(&psi);
        big::BIG::invmodp(&mut psi_inv, &self.r);
        new_sigma.Z = ecp::ECP::mul(&new_sigma.Z, &rho);
        new_sigma.Z = ecp::ECP::mul(&new_sigma.Z, &psi);
        new_sigma.Y = ecp::ECP::mul(&new_sigma.Y, &psi_inv);
        new_sigma.Yhat = ecp2::ECP2::mul(&new_sigma.Yhat, &psi_inv);
        return new_sigma;
    }

    pub fn ChangeRepresentation(
        &self,
        M: Vec<ecp::ECP>,
        sigma: signature,
        mu: &big::BIG,
        rng: &mut rand::RAND,
    ) -> (Vec<ecp::ECP>, signature) {
        // changes the representation of the equivalence class for M & sigma
        let mut new_sigma = sigma;
        let mut new_M = M;
        let psi = big::BIG::randomnum(&self.r, rng);
        let mut psi_inv = big::BIG::new_copy(&psi);
        big::BIG::invmodp(&mut psi_inv, &self.r);
        for i in 0..self.ell {
            new_M[i] = ecp::ECP::mul(&new_M[i], &mu);
        }
        new_sigma.Z = ecp::ECP::mul(&new_sigma.Z, &mu);
        new_sigma.Z = ecp::ECP::mul(&new_sigma.Z, &psi);
        new_sigma.Y = ecp::ECP::mul(&new_sigma.Y, &psi_inv);
        new_sigma.Yhat = ecp2::ECP2::mul(&new_sigma.Yhat, &psi_inv);
        return (new_M, new_sigma);
    }
}
