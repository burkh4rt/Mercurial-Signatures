#include <assert.h>

#include "miracl_core_c_bn254/pair_BN254.h"
#include "miracl_core_c_bn254/big_256_56.h"

typedef ECP_BN254 ECP;
typedef ECP2_BN254 ECP2;
typedef FP12_BN254 FP12;
typedef BIG_256_56 BIG;

/* signature type */
typedef struct {ECP Z; ECP Y; ECP2 Yhat;} sigma_t;

/* public parameters */
typedef struct {ECP P; ECP2 Phat; BIG r;} PP_t;

/* hard-code key (& message) length */
#define ell 4

/* generate public key pk, secret key sk pairing as arrays of length ell */
void KeyGen(PP_t * PP, ECP2 *pk, BIG *sk, csprng *rng) {
    for (int i = 0; i < ell; i++) {
        BIG_256_56_randomnum(sk[i], PP->r, rng);
        ECP2_BN254_copy(&pk[i], &PP->Phat);
        ECP2_BN254_mul(&pk[i], sk[i]);
    };
};

/* sign a message M with sk */
void Sign(PP_t * PP, BIG *sk, ECP * M, sigma_t * sigma, csprng *rng) {
    BIG y, y_inv;
    ECP factor;
    BIG_256_56_randomnum(y, PP->r, rng);
    BIG_256_56_invmodp(y_inv, y, PP->r);
    ECP_BN254_copy(&(sigma->Z), &M[0]);
    ECP_BN254_mul(&(sigma->Z), sk[0]);
    for (int i = 1; i < ell; i++) {
        ECP_BN254_copy(&factor, &M[i]);
        ECP_BN254_mul(&factor,sk[i]);
        ECP_BN254_add(&(sigma->Z),&factor);
    };
    ECP_BN254_mul(&(sigma->Z),y);
    ECP_BN254_copy(&(sigma->Y), &PP->P);
    ECP2_BN254_copy(&(sigma->Yhat), &PP->Phat);
    ECP_BN254_mul(&(sigma->Y), y_inv);
    ECP2_BN254_mul(&(sigma->Yhat), y_inv);
};

/* verify that signature sigma is valid for pk and M */
bool Verify(PP_t * PP, ECP2 *pk, ECP * M, sigma_t * sigma) {
    FP12 q1, q2, q3, q4, factor;
    PAIR_BN254_ate(&q1, &pk[0], &M[0]);
    PAIR_BN254_fexp(&q1);
    for (int i = 1; i < ell; i++) {
        PAIR_BN254_ate(&factor, &pk[i], &M[i]);
        PAIR_BN254_fexp(&factor);
        FP12_BN254_mul(&q1, &factor);
    };
    PAIR_BN254_ate(&q2, &(sigma->Yhat), &(sigma->Z));
    PAIR_BN254_fexp(&q2);
    PAIR_BN254_ate(&q3, &PP->Phat, &(sigma->Y));
    PAIR_BN254_fexp(&q3);
    PAIR_BN254_ate(&q4, &(sigma->Yhat), &PP->P);
    PAIR_BN254_fexp(&q4);
    return (bool) FP12_BN254_equals(&q1,&q2) & (bool) FP12_BN254_equals(&q3,&q4);
};

/* convert sk with randomness rho */
void ConvertSK(PP_t * PP, BIG *sk, BIG rho) {
    for (int i = 0; i < ell; i++) {
        BIG_256_56_modmul(sk[i], sk[i], rho, PP->r);
    };
};

/* convert pk with randomness rho */
void ConvertPK(PP_t * PP, ECP2 *pk, BIG rho) {
    for (int i = 0; i < ell; i++) {
        ECP2_BN254_mul(&pk[i], rho);
    };
};

/* convert signature sigma */
void ConvertSig(PP_t * PP, ECP2 *pk, ECP * M, sigma_t * sigma, BIG rho, csprng *rng) {
    BIG psi, psi_inv;
    BIG_256_56_randomnum(psi, PP->r, rng);
    BIG_256_56_invmodp(psi_inv, psi, PP->r);
    ECP_BN254_mul(&(sigma->Z), rho);
    ECP_BN254_mul(&(sigma->Z), psi);
    ECP_BN254_mul(&(sigma->Y), psi_inv);
    ECP2_BN254_mul(&(sigma->Yhat), psi_inv);
};

/* change representation of equivalence class for M & sigma */
void ChangeRep(PP_t * PP, ECP2 *pk, ECP * M, sigma_t * sigma, BIG mu, csprng *rng) {
    BIG psi, psi_inv;
    BIG_256_56_randomnum(psi, PP->r, rng);
    BIG_256_56_invmodp(psi_inv, psi, PP->r);
    for (int i = 0; i < ell; i++) {
        ECP_BN254_mul(&M[i], mu);
    };
    ECP_BN254_mul(&(sigma->Z), mu);
    ECP_BN254_mul(&(sigma->Z), psi);
    ECP_BN254_mul(&(sigma->Y), psi_inv);
    ECP2_BN254_mul(&(sigma->Yhat), psi_inv);
};


int main() {
    // initialize rng
    csprng RNG;
    char pr[10];
    for (int i = 1; i < 10; i++) pr[i] = (char) random();
    RAND_seed(&RNG, 10, pr);

    // initialize scheme public parameters
    PP_t PP;
    ECP2_BN254_generator(&PP.Phat);
    ECP_BN254_generator(&PP.P);
    BIG_256_56_rcopy(PP.r, CURVE_Order_BN254);

    // allocate signature
    sigma_t sigma;

    // generate random message
    ECP M[ell];
    BIG rand;
    for (int j=0; j<ell; j++) {
        BIG_256_56_randomnum(rand, PP.r, &RNG);
        ECP_BN254_hap2point(&M[j], rand);
    }


    // test KeyGen(), Sign(), and Verify()
    BIG sk[ell];
    ECP2 pk[ell];
    KeyGen(&PP, pk, sk, &RNG);
    Sign(&PP,sk,M,&sigma,&RNG);
    assert(Verify(&PP,pk,M,&sigma));

    // test ConvertPK() and ConvertSig()
    BIG rho;
    BIG_256_56_randomnum(rho, PP.r, &RNG);
    ConvertPK(&PP,pk, rho);
    ConvertSig(&PP,pk,M,&sigma,rho,&RNG);
    assert(Verify(&PP,pk,M,&sigma));

    // test ChangeRep()
    BIG mu;
    BIG_256_56_randomnum(mu, PP.r, &RNG);
    ChangeRep(&PP,pk,M,&sigma,mu,&RNG);
    assert(Verify(&PP,pk,M,&sigma));

    // test ConvertSK(), ConvertPK(), and Verify
    KeyGen(&PP, pk, sk, &RNG);
    BIG_256_56_randomnum(rho, PP.r, &RNG);
    ConvertPK(&PP,pk, rho);
    ConvertSK(&PP,sk, rho);
    Sign(&PP,sk,M,&sigma,&RNG);
    assert(Verify(&PP,pk,M,&sigma));

    return 0;
}