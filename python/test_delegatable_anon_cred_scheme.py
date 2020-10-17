import unittest

from delegatable_anon_cred_scheme import DelegatableAnonCredScheme


class TestMercurialSignatureScheme(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.DAC1 = DelegatableAnonCredScheme(2)
        cls.DAC2 = DelegatableAnonCredScheme(3)
        cls.DAC3 = DelegatableAnonCredScheme(4)

    def test_chain(self):
        for DAC in [self.DAC1, self.DAC2, self.DAC3]:

            # user 1 generates keys, nyms, & gets on the credential chain
            even_keys1, odd_keys1 = DAC.KeyGen()
            (nym_even1, sk_even1), (nym_odd1, sk_odd1) = DAC.NymGen(
                *even_keys1, *odd_keys1
            )
            cred_chain = DAC.IssueFirst(nym_odd1)
            self.assertTrue(DAC.VerifyChain(cred_chain), "user 1 checks out")

            # user 2 generates keys, nyms, & gets on the credential chain
            even_keys2, odd_keys2 = DAC.KeyGen()
            (nym_even2, sk_even2), (nym_odd2, sk_odd2) = DAC.NymGen(
                *even_keys2, *odd_keys2
            )
            cred_chain = DAC.IssueNext(cred_chain, nym_even2, sk_odd1)
            self.assertTrue(DAC.VerifyChain(cred_chain), "user 2 is a-ok")

            # user 3 generates keys, nyms, & gets on the credential chain
            even_keys3, odd_keys3 = DAC.KeyGen()
            (nym_even3, sk_even3), (nym_odd3, sk_odd3) = DAC.NymGen(
                *even_keys3, *odd_keys3
            )
            cred_chain = DAC.IssueNext(cred_chain, nym_odd3, sk_even2)
            self.assertTrue(DAC.VerifyChain(cred_chain), "go for user 3")

            # user 4 generates keys, nyms, & gets on the credential chain
            even_keys4, odd_keys4 = DAC.KeyGen()
            (nym_even4, sk_even4), (nym_odd4, sk_odd4) = DAC.NymGen(
                *even_keys4, *odd_keys4
            )
            cred_chain = DAC.IssueNext(cred_chain, nym_even4, sk_odd3)
            self.assertTrue(DAC.VerifyChain(cred_chain), "go for user 4")

            # user 5 generates keys, nyms, & gets on the credential chain
            even_keys5, odd_keys5 = DAC.KeyGen()
            (nym_even5, sk_even5), (nym_odd5, sk_odd5) = DAC.NymGen(
                *even_keys5, *odd_keys5
            )
            cred_chain = DAC.IssueNext(cred_chain, nym_odd5, sk_even4)
            self.assertTrue(DAC.VerifyChain(cred_chain), "go for user 5")


if __name__ == "__main__":
    unittest.main()
