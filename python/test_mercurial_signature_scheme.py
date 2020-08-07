import unittest

from mercurial_signature_scheme import MercurialSignatureScheme, MercurialSignatureDual


class TestMercurialSignatureScheme(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.MSS1 = MercurialSignatureScheme()
        cls.MSS2 = MercurialSignatureDual()

    def test_verify(self):
        for MSS in [self.MSS1, self.MSS2]:
            pk, sk = MSS.KeyGen(3)
            M = [MSS.HashMessage(m) for m in ["this", "is a", "test"]]
            sigma = MSS.Sign(sk, M)
            self.assertTrue(MSS.Verify(pk, M, sigma), "test message signature verifies")

    def test_convert_sig(self):
        for MSS in [self.MSS1, self.MSS2]:
            pk, sk = MSS.KeyGen(4)
            M = [MSS.HashMessage(m) for m in ["this", "is", "another", "test"]]
            sigma = MSS.Sign(sk, M)
            rho = MSS.RandomZp()
            pk1 = MSS.ConvertPK(pk, rho)
            sigma1 = MSS.ConvertSig(pk, M, sigma, rho)
            self.assertTrue(MSS.Verify(pk1, M, sigma1), "test conversion verifies")
            M[0] = MSS.HashMessage("oh noes")
            self.assertFalse(MSS.Verify(pk1, M, sigma1), "forgery does not verify")

    def test_change_rep(self):
        for MSS in [self.MSS1, self.MSS2]:
            pk, sk = MSS.KeyGen(5)
            M = [MSS.HashMessage(m) for m in ["this", "is", "also", "a", "test"]]
            sigma = MSS.Sign(sk, M)
            mu = MSS.RandomZp()
            M0, sigma0 = MSS.ChangeRep(pk, M, sigma, mu)
            self.assertTrue(MSS.Verify(pk, M0, sigma0), "change rep verifies")
            M0[-1] = MSS.HashMessage("is bad")
            self.assertFalse(MSS.Verify(pk, M0, sigma0), "forgery does not verify")

    def test_underlying_groups(self):
        for MSS in [self.MSS1]:  # same groups for both signature schemes
            self.assertEqual(
                (MSS.curve.r + 1) * MSS.P, MSS.P, "ecp group order check passes"
            )
            self.assertEqual(
                (MSS.curve.r + 1) * MSS.Phat, MSS.Phat, "ecp2 group order check passes"
            )

    def test_hash(self):
        for MSS in [self.MSS1]:  # the real hash
            self.assertEqual(MSS.HashMessage("foo"), MSS.HashMessage("foo"))
            self.assertEqual(MSS.HashMessage("bar"), MSS.HashMessage("bar"))
        for MSS in [self.MSS1, self.MSS2]:
            self.assertNotEqual(MSS.HashMessage("foo"), MSS.HashMessage("bar"))
            self.assertNotEqual(MSS.HashMessage("bar"), MSS.HashMessage("baz"))


if __name__ == "__main__":
    unittest.main()
