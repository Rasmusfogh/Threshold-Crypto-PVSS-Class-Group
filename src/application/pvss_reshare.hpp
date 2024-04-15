#ifndef PVSS_RESHARE_HPP__
#define PVSS_RESHARE_HPP__

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

        unique_ptr<EncShares> reshare(const EncShares&);

        bool verifyResharing(const EncShares& enc_shares) const;

      private:
        /* Pre-computation of lamdas */
        void compute_lambdas(vector<Mpz>& lambdas, const size_t n,
            const size_t t, const Mpz& q);
    };
}    // namespace Application

#endif