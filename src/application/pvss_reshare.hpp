#ifndef PVSS_RESHARE_HPP__
#define PVSS_RESHARE_HPP__

#include <qclpvss.hpp>

using namespace QCLPVSS_;

namespace Application {
    template <typename C>
    class PVSS_Reshare : private QCLPVSS<C> {

      public:
        size_t n0_, t0_, n1_, t1_;

        vector<unique_ptr<const CL_HSM_SecretKey<C>>> sks;
        vector<unique_ptr<const CL_HSM_PublicKey<C>>> pks;
        vector<unique_ptr<NizkDL<C>>> keygen_pf;

        unique_ptr<EncShares<C>> enc_shares;

      public:
        PVSS_Reshare(const SecLevel& seclevel, HashAlgo& hash, RandGen& rand,
            const Mpz& q, const size_t n, const size_t t);

        using QCLPVSS<C>::decShare;
        using QCLPVSS<C>::dist;
        using QCLPVSS<C>::keyGen;
        using QCLPVSS<C>::verifyKey;

        unique_ptr<EncShares<C>> reshare(EncShares<C>&, size_t n1,
            size_t t1) const;

      protected:
        void generateCoefficients(vector<Mpz>& coeffs, size_t t) const;
    };
}    // namespace Application

#endif