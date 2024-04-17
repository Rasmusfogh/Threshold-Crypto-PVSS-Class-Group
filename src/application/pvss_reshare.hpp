#ifndef PVSS_RESHARE_HPP__
#define PVSS_RESHARE_HPP__

#include "nizk_resh.hpp"
#include "qclpvss.hpp"

using namespace QCLPVSS_;

namespace Application {
    class PVSS_Reshare : private QCLPVSS {

      public:
        size_t n0_, t0_, n1_, t1_;

        vector<unique_ptr<const SecretKey>> sks;
        vector<unique_ptr<const PublicKey>> pks;
        vector<unique_ptr<NizkDL>> keygen_pf;

        unique_ptr<EncShares> enc_shares;

        vector<Mpz> Vis_reshare_;
        vector<Mpz> lambdas_;

        Mpz secret_;

      public:
        PVSS_Reshare(const SecLevel& seclevel, HashAlgo& hash, RandGen& rand,
            const Mpz& q, const size_t n0, const size_t t0, const size_t n1,
            const size_t t1);

        unique_ptr<vector<EncSharesResh>> reshare(const EncShares&) const;
        bool verifyReshare(const vector<EncSharesResh>&,
            const EncShares&) const;
        unique_ptr<EncShares> distReshare(const vector<EncSharesResh>&) const;
        bool verifyDistReshare(const EncShares& enc_share) const;

      private:
        /* Pre-computation of lamdas */
        void compute_lambdas(vector<Mpz>& lambdas, const size_t n,
            const size_t t, const Mpz& q);
    };
}    // namespace Application

#endif