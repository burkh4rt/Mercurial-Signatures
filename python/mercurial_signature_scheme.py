import functools
import hashlib

from bn254 import big
from bn254 import curve
from bn254 import ecp
from bn254 import ecp2
from bn254 import fp12
from bn254 import pair


class MercurialSignatureScheme:
    def __init__(self):
        self.G1 = ecp.ECp()
        self.G2 = ecp2.ECp2()
        self.GT = fp12.Fp12()
        self.P = ecp.generator().copy()
        self.Phat = ecp2.generator().copy()
        self.e = pair.e
        self.curve = curve

    def KeyGen(self, ell):
        sk = []
        pk = []
        for _ in range(ell):
            x = self.RandomZp()
            w = x * self.Phat
            sk.append(x)
            pk.append(w)
        return pk, sk

    def Sign(self, sk, M):
        y = self.RandomZp()
        Z = y * functools.reduce(
            lambda a, b: a.add(b), [xi * Mi for xi, Mi in zip(sk, M)]
        )
        Y = big.invmodp(y, self.curve.r) * self.P
        Yhat = big.invmodp(y, self.curve.r) * self.Phat
        return Z, Y, Yhat

    def Verify(self, pk, M, sigma):
        Z, Y, Yhat = sigma
        q1 = functools.reduce(
            lambda a, b: a * b, [self.e(Xi, Mi) for Xi, Mi in zip(pk, M)]
        )
        return q1 == self.e(Yhat, Z) and self.e(self.Phat, Y) == self.e(Yhat, self.P)

    def ConvertSK(self, sk, rho):
        return [rho * xi for xi in sk]

    def ConvertPK(self, pk, rho):
        return [rho * Xi for Xi in pk]

    def ConvertSig(self, pk, M, sigma, rho):
        Z, Y, Yhat = sigma
        psi = self.RandomZp()
        return (
            psi * rho * Z,
            big.invmodp(psi, self.curve.r) * Y,
            big.invmodp(psi, self.curve.r) * Yhat,
        )

    def ChangeRep(self, pk, M, sigma, mu):
        Z, Y, Yhat = sigma
        psi = self.RandomZp()
        M0 = [mu * m for m in M]
        sigma0 = (
            psi * mu * Z,
            big.invmodp(psi, self.curve.r) * Y,
            big.invmodp(psi, self.curve.r) * Yhat,
        )
        return M0, sigma0

    @staticmethod
    def HashMessage(m):
        h = hashlib.shake_256()
        h.update(bytes(m, "utf-8"))
        hm = big.from_bytes(h.digest(curve.EFS))
        HM = ecp.ECp()
        while not HM.set(hm):
            hm = hm + 1
        HM = curve.CurveCof * HM
        return HM

    @staticmethod
    def RandomZp():
        return big.rand(curve.r)


class MercurialSignatureDual(MercurialSignatureScheme):
    def KeyGen(self, ell):
        sk = []
        pk = []
        for _ in range(ell):
            x = self.RandomZp()
            w = x * self.P
            sk.append(x)
            pk.append(w)
        return pk, sk

    def Sign(self, sk, M):
        y = self.RandomZp()
        Z = y * functools.reduce(
            lambda a, b: a.add(b), [Xi * Mi for Xi, Mi in zip(sk, M)]
        )
        Y = big.invmodp(y, self.curve.r) * self.Phat
        Yhat = big.invmodp(y, self.curve.r) * self.P
        return Z, Y, Yhat

    def Verify(self, pk, M, sigma):
        Z, Y, Yhat = sigma
        q1 = functools.reduce(
            lambda a, b: a * b, [self.e(Mi, Xi) for Xi, Mi in zip(pk, M)]
        )
        return q1 == self.e(Z, Yhat) and self.e(Y, self.P) == self.e(self.Phat, Yhat)

    @staticmethod
    def HashMessage(m):
        # not a real hash but sufficient for testing purposes
        return big.rand(curve.r) * ecp2.generator().copy()
