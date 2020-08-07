from mercurial_signature_scheme import MercurialSignatureScheme, MercurialSignatureDual


class DelegatableAnonCredScheme:
    def __init__(self, ell):
        self.MSS1 = MercurialSignatureScheme()
        self.MSS2 = MercurialSignatureDual()
        self.ell = ell
        self.pk0, self.sk0 = self.MSS2.KeyGen(self.ell)
        self.nym0 = (self.pk0, None)

    def KeyGen(self):
        pk_even, sk_even = self.MSS2.KeyGen(self.ell)
        pk_odd, sk_odd = self.MSS1.KeyGen(self.ell)
        return (pk_even, sk_even), (pk_odd, sk_odd)

    def NymGen(self, pk_even, sk_even, pk_odd, sk_odd):
        rho_even = self.MSS2.RandomZp()
        sk_even = self.MSS2.ConvertSK(sk_even, rho_even)
        nym_even = self.MSS2.ConvertPK(pk_even, rho_even)
        rho_odd = self.MSS1.RandomZp()
        sk_odd = self.MSS1.ConvertSK(sk_odd, rho_odd)
        nym_odd = self.MSS1.ConvertPK(pk_odd, rho_odd)
        return (nym_even, sk_even), (nym_odd, sk_odd)

    def IssueFirst(self, nym1):
        sig1 = self.MSS2.Sign(self.sk0, nym1)
        return [nym1], [sig1]

    def IssueNext(self, cred_chain, new_nym, sk):
        nym_list, sig_list = cred_chain
        assert len(nym_list) == len(sig_list)
        rho = self.MSS2.RandomZp()
        nym_list[0], sig_list[0] = self.MSS2.ChangeRep(
            self.pk0, nym_list[0], sig_list[0], rho
        )
        assert self.MSS2.Verify(self.pk0, nym_list[0], sig_list[0])
        for i in range(len(nym_list) - 1):
            # Note: MSS1 & MSS2 share the same functions RandomZp, ChangeRep, & ConvertSig
            MSS = self.MSS1 if i % 2 == 0 else self.MSS2
            sig_tilde = MSS.ConvertSig(
                nym_list[i], nym_list[i + 1], sig_list[i + 1], rho
            )
            rho = MSS.RandomZp()
            nym_list[i + 1], sig_list[i + 1] = MSS.ChangeRep(
                nym_list[i], nym_list[i + 1], sig_tilde, rho
            )
            assert MSS.Verify(nym_list[i], nym_list[i + 1], sig_list[i + 1])
        nym_list.append(new_nym)
        MSS = self.MSS1 if len(nym_list) % 2 == 0 else self.MSS2
        sk = MSS.ConvertSK(sk, rho)
        sig_list.append(MSS.Sign(sk, new_nym))
        assert MSS.Verify(nym_list[-2], nym_list[-1], sig_list[-1])
        return nym_list, sig_list

    def VerifyChain(self, cred_chain):
        nym_list, sig_list = cred_chain
        assert len(nym_list) == len(sig_list)
        if not self.MSS2.Verify(self.pk0, nym_list[0], sig_list[0]):
            return False
        for i in range(len(nym_list) - 1):
            MSS = self.MSS1 if i % 2 == 0 else self.MSS2
            if not MSS.Verify(nym_list[i], nym_list[i + 1], sig_list[i + 1]):
                return False
        return True
