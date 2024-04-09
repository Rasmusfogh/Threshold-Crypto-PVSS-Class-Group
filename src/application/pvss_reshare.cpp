#include "pvss_reshare.hpp"
#include "nizk_resh.hpp"

using namespace Application;
using namespace NIZK;

PVSS_Reshare::PVSS_Reshare(const SecLevel& seclevel, HashAlgo& hash,
    RandGen& rand, const Mpz& q, const size_t n0, const size_t t0)
    : QCLPVSS(seclevel, hash, rand, q, 1, n0, t0), sks(n0), pks(n0),
      keygen_pf(n0), n0_(n0), t0_(t0) {

    for (size_t i = 0; i < n0_; i++) {
        sks[i] = this->keyGen(randgen_);
        pks[i] = this->keyGen(*sks[i]);
        keygen_pf[i] = this->keyGen(*pks[i], *sks[i]);

        if (!this->verifyKey(*pks[i], *keygen_pf[i]))
            throw std::invalid_argument("Verifying  key pair failed.");
    }

    Mpz secret(9898UL);

    enc_shares = this->dist(secret, pks);
}

unique_ptr<EncShares> PVSS_Reshare::reshare(const EncShares& enc_shares,
    const size_t n1, const size_t t1) {

    vector<unique_ptr<DecShare>> dec_shares(n0_);

    for (size_t j = 0; j < n0_; j++) {
        dec_shares[j] = this->decShare(*pks[j], *sks[j], enc_shares.R,
            *enc_shares.Bs->at(j), j);

        auto shares =
            this->sss_.shareSecret(dec_shares[j]->sh->y(), t1, n1, q_);

        auto enc_shares_j = this->EncryptShares(*shares, pks);

        unique_ptr<NizkResh> pf = unique_ptr<NizkResh>(
            new NizkResh(hash_, randgen_, *this, seclevel_, n1, t1, q_, Vis_));

        auto witness = tie(*sks[j], enc_shares_j->r, *shares);

        pf->prove(witness, pks, *pks[j], enc_shares.R, *enc_shares.Bs->at(j),
            enc_shares_j->R, *enc_shares_j->Bs);

        // Set proof on EncShares. Make that shiet template based. Then return
        // it.
    }
}

void PVSS_Reshare::generateCoefficients(vector<Mpz>& coeffs, size_t t) const {
    for (size_t _ = 1; _ < t; _++)
        coeffs.emplace_back(randgen_.random_mpz(q_));
}
