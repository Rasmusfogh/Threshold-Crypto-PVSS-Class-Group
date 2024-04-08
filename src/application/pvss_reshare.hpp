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

      public:
        PVSS_Reshare(const SecLevel& seclevel, HashAlgo& hash, RandGen& rand,
            const Mpz& q, const size_t n, const size_t t);

        using QCLPVSS::decShare;
        using QCLPVSS::dist;
        using QCLPVSS::keyGen;
        using QCLPVSS::verifyKey;

        unique_ptr<EncShares> reshare(EncShares&, size_t n1, size_t t1);

      protected:
        void generateCoefficients(vector<Mpz>& coeffs, size_t t) const;
    };
}    // namespace Application

#endif