extern crate core;

use core::bn254::{big, ecp, ecp2, pair, rom};
use core::rand;

#[allow(non_snake_case, non_camel_case_types)]
// #[derive(Debug)]
struct signature {
    // a mercurial signature
    Z: ecp::ECP,
    Y: ecp::ECP,
    Yhat: ecp2::ECP2,
}

#[allow(non_snake_case, non_camel_case_types)]
// #[derive(Debug)]
struct public_parameters {
    // public parameters
    P: ecp::ECP,      // generator for the first group
    Phat: ecp2::ECP2, // generator for the paired group
    r: big::BIG,      // order of the isomorphic groups
}

#[allow(non_upper_case_globals)]
const ell: usize = 4; // length of the public key, secret key, and messages

#[allow(non_snake_case, non_camel_case_types)]
fn KeyGen(PP: &public_parameters, rng: &mut rand::RAND) -> (Vec<big::BIG>, Vec<ecp2::ECP2>) {
    // generates secret key sk, public key pk pair
    let mut sk: Vec<big::BIG> = Vec::with_capacity(ell);
    let mut pk: Vec<ecp2::ECP2> = Vec::with_capacity(ell);
    for _ in 0..ell {
        let x = big::BIG::randomnum(&PP.r, rng);
        let mut w = ecp2::ECP2::new();
        w.copy(&PP.Phat);
        sk.push(x);
        pk.push(ecp2::ECP2::mul(&w, &x));
    }
    return (sk, pk);
}

#[allow(non_snake_case, non_camel_case_types)]
fn Sign(
    PP: &public_parameters,
    sk: &Vec<big::BIG>,
    M: &Vec<ecp::ECP>,
    rng: &mut rand::RAND,
) -> signature {
    // signs a message M using secret key sk
    let y = big::BIG::randomnum(&PP.r, rng);
    let mut y_inv = big::BIG::new_copy(&y);
    big::BIG::invmodp(&mut y_inv, &PP.r);
    let mut Z = M[0].mul(&sk[0]);
    for i in 1..ell {
        Z.add(&(M[i].mul(&sk[i])));
    }
    Z = Z.mul(&y);
    let Y = (PP.P).mul(&y_inv);
    let Yhat = (PP.Phat).mul(&y_inv);
    let sigma = signature {
        Z: Z,
        Y: Y,
        Yhat: Yhat,
    };
    return sigma;
}

#[allow(non_snake_case, non_camel_case_types)]
fn Verify(
    PP: &public_parameters,
    pk: &Vec<ecp2::ECP2>,
    M: &Vec<ecp::ECP>,
    sigma: &signature,
) -> bool {
    // verfies that the signature sigma corresponds to public key pk
    // and message M
    let Z = &sigma.Z;
    let Y = &sigma.Y;
    let Yhat = &sigma.Yhat;
    let mut q1 = pair::fexp(&pair::ate(&pk[0], &M[0]));
    for i in 1..ell {
        q1.mul(&pair::fexp(&pair::ate(&pk[i], &M[i])));
    }
    let q2 = pair::fexp(&pair::ate(&Yhat, &Z));
    let q3 = pair::fexp(&pair::ate(&PP.Phat, &Y));
    let q4 = pair::fexp(&pair::ate(&Yhat, &PP.P));
    return q1.equals(&q2) && q3.equals(&q4);
}

#[allow(non_snake_case, non_camel_case_types)]
fn ConvertSK(PP: &public_parameters, sk: Vec<big::BIG>, rho: &big::BIG) -> Vec<big::BIG> {
    // converts sk with randomness rho
    let mut new_sk = sk;
    for i in 0..ell {
        new_sk[i] = big::BIG::modmul(&new_sk[i], &rho, &PP.r);
    }
    return new_sk;
}

#[allow(non_snake_case, non_camel_case_types)]
fn ConvertPK(PP: &public_parameters, pk: Vec<ecp2::ECP2>, rho: &big::BIG) -> Vec<ecp2::ECP2> {
    // converts pk with randomness rho
    let mut new_pk = pk;
    for i in 0..ell {
        new_pk[i] = ecp2::ECP2::mul(&new_pk[i], &rho);
    }
    return new_pk;
}

#[allow(non_snake_case, non_camel_case_types)]
fn ConvertSignature(
    PP: &public_parameters,
    pk: &Vec<ecp2::ECP2>,
    M: &Vec<ecp::ECP>,
    sigma: signature,
    rho: &big::BIG,
    rng: &mut rand::RAND,
) -> signature {
    // converts sigma with randomness rho
    let mut new_sigma = sigma;
    let psi = big::BIG::randomnum(&PP.r, rng);
    let mut psi_inv = big::BIG::new_copy(&psi);
    big::BIG::invmodp(&mut psi_inv, &PP.r);
    new_sigma.Z = ecp::ECP::mul(&new_sigma.Z, &rho);
    new_sigma.Z = ecp::ECP::mul(&new_sigma.Z, &psi);
    new_sigma.Y = ecp::ECP::mul(&new_sigma.Y, &psi_inv);
    new_sigma.Yhat = ecp2::ECP2::mul(&new_sigma.Yhat, &psi_inv);
    return new_sigma;
}

#[allow(non_snake_case, non_camel_case_types)]
fn ChangeRepresentation(
    PP: &public_parameters,
    pk: &Vec<ecp2::ECP2>,
    M: Vec<ecp::ECP>,
    sigma: signature,
    mu: &big::BIG,
    rng: &mut rand::RAND,
) -> (Vec<ecp::ECP>, signature) {
    // changes the representation of the equivalence class for M & sigma
    let mut new_sigma = sigma;
    let mut new_M = M;
    let psi = big::BIG::randomnum(&PP.r, rng);
    let mut psi_inv = big::BIG::new_copy(&psi);
    big::BIG::invmodp(&mut psi_inv, &PP.r);
    for i in 0..ell {
        new_M[i] = ecp::ECP::mul(&new_M[i], &mu);
    }
    new_sigma.Z = ecp::ECP::mul(&new_sigma.Z, &mu);
    new_sigma.Z = ecp::ECP::mul(&new_sigma.Z, &psi);
    new_sigma.Y = ecp::ECP::mul(&new_sigma.Y, &psi_inv);
    new_sigma.Yhat = ecp2::ECP2::mul(&new_sigma.Yhat, &psi_inv);
    return (new_M, new_sigma);
}

#[allow(non_snake_case, non_camel_case_types)]
fn prepare_rng() -> core::rand::RAND {
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
fn main() {
    // initialize rng
    let mut rng = prepare_rng();

    // initialize public parameters
    let PP = public_parameters {
        P: ecp::ECP::generator(),
        Phat: ecp2::ECP2::generator(),
        r: big::BIG::new_ints(&rom::CURVE_ORDER),
    };

    // println!("{:?}", PP);

    // generate random message
    #[allow(non_snake_case, non_camel_case_types)]
    let mut M: Vec<ecp::ECP> = Vec::with_capacity(ell);
    for _ in 0..ell {
        let mut Mj = ecp::ECP::new();
        Mj.copy(&PP.P);
        let rand = big::BIG::randomnum(&PP.r, &mut rng);
        Mj = Mj.mul(&rand);
        M.push(Mj);
    }

    // println!("{:?}", M);

    // test KeyGen(), Sign(), and Verify()
    let (sk, pk) = KeyGen(&PP, &mut rng);
    let sigma = Sign(&PP, &sk, &M, &mut rng);
    assert!(Verify(&PP, &pk, &M, &sigma));

    // test ConvertPK() and ConvertSignature()
    let rho = big::BIG::randomnum(&PP.r, &mut rng);
    let new_pk = ConvertPK(&PP, pk, &rho);
    let new_sig = ConvertSignature(&PP, &new_pk, &M, sigma, &rho, &mut rng);
    assert!(Verify(&PP, &new_pk, &M, &new_sig));

    // test ChangeRepresentation()
    let mu = big::BIG::randomnum(&PP.r, &mut rng);
    let (new_M, new_sig) = ChangeRepresentation(&PP, &new_pk, M, new_sig, &mu, &mut rng);
    assert!(Verify(&PP, &new_pk, &new_M, &new_sig));

    // test ConvertSK(), ConvertPK(), and Verify
    let (sk, pk) = KeyGen(&PP, &mut rng);
    let rho = big::BIG::randomnum(&PP.r, &mut rng);
    let new_pk = ConvertPK(&PP, pk, &rho);
    let new_sk = ConvertSK(&PP, sk, &rho);
    let sigma = Sign(&PP, &new_sk, &new_M, &mut rng);
    assert!(Verify(&PP, &new_pk, &new_M, &sigma));
}
