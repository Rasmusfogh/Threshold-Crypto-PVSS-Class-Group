#include <pvss_reshare.hpp>

using namespace Application;

template <typename C>
PVSS_Reshare<C>::PVSS_Reshare(const SecLevel& seclevel, HashAlgo& hash,
    RandGen& rand, const Mpz& q, const size_t n0, const size_t t0)
    : QCLPVSS<C>(seclevel, hash, rand, q, 1, n0, t0), sks(n0), pks(n0),
      keygen_pf(n0), n0_(n0), t0_(t0) {

    for (size_t i = 0; i < n0_; i++) {
        sks[i] = this.keyGen(this.randgen_);
        pks[i] = this.keyGen(*sks[i]);
        keygen_pf[i] = this.keyGen(*pks[i], *sks[i]);

        if (!this.verifyKey(*pks[i], *keygen_pf[i]))
            throw std::invalid_argument("Verifying  key pair failed.");
    }

    Mpz secret(9898UL);

    enc_shares = this.dist(secret, pks);
}

template <typename C>
unique_ptr<EncShares<C>> PVSS_Reshare<C>::reshare(EncShares<C>& enc_shares,
    size_t n1, size_t t1) const {

    vector<unique_ptr<DecShare<C>>> dec_shares(n0_);

    for (size_t j = 0; j < n0_; j++) {
        dec_shares[j] = this->decShare(*pks[j], *sks[j], enc_shares.R,
            *enc_shares.Bs->at(j), j);

        vector<Mpz> coeffs;
        coeffs.reserve(t1);

        // p_j(\beta) = sigma_j = the share
        coeffs.emplace_back(dec_shares[j]->sh->y());
        this.generateCoefficients(coeffs, t1);
    }
}

template <typename C>
void PVSS_Reshare<C>::generateCoefficients(vector<Mpz>& coeffs,
    size_t t) const {
    for (size_t _ = 1; _ < t; _++)
        coeffs.emplace_back(this.randgen_.random_mpz(this.q_));
}
