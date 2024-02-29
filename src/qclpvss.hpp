#ifndef QCLPVSS__
#define QCLPVSS__

#include <iostream>
#include <memory>
#include "utils/qclpvss_utils.hpp"
#include "utils/sss.hpp"
#include "nizk/nizkpok_dl.hpp"
#include "nizk/nizk_sh.hpp"

using namespace BICYCL;
using namespace OpenSSL;
using namespace UTILS;
using namespace NIZK;
using namespace std;
using namespace SSS_;

namespace QCLPVSS_
{   
    class QCLPVSS 
    {
        public:

        SSS sss_;
        CL_HSMqk cl_hsmqk_;
        SecLevel& seclevel_;

        const size_t k_;
        /** number of parties. n + k <= q*/
        const size_t n_;
        /** privacy threshold. k + t <= n*/
        const size_t t_;

        const Mpz& q_;

        //fixed points used to evaluate the sharing polynomial for the sharing proof
        vector<unique_ptr<Mpz>> Vis_;

        HashAlgo & hash_;
        RandGen & randgen_;

        //Public parameters in dist
        unique_ptr<QFI> R_;
        vector<unique_ptr<QFI>> Bs_;

        //public parameters in decShare
        unique_ptr<QFI> fi_;


        public:

        /** Constructor is Setup(). @p q: prime and > 2^seclevel @p k: size of secret, @p t: privacy threshhold, @p n: number of parties  */
        QCLPVSS (SecLevel, HashAlgo &, RandGen&, Mpz &q, const size_t k,
             const size_t n, const size_t t, bool compact_variant);


        /** @name Cryptographic functionalities 
         * @{
         * */ 

        //Setup
        unique_ptr<const SecretKey> keyGen(RandGen&) const;
        unique_ptr<const PublicKey> keyGen(const SecretKey&) const;
        unique_ptr<NizkPoK_DL> keyGen(const PublicKey&, const SecretKey&) const;
        bool verifyKey(const PublicKey&, unique_ptr<NizkPoK_DL>) const;

        //Distribution
        unique_ptr<vector<unique_ptr<const Share>>> dist(const Mpz &s) const;
        unique_ptr<Nizk_SH> dist(vector<unique_ptr<const PublicKey>>&, vector<unique_ptr<const Share>>&) const;

        //Distribution Verification
        bool verifySharing(vector<unique_ptr<const PublicKey>>&, unique_ptr<Nizk_SH>) const;

        //Reconstruction
        unique_ptr<const Share> decShare(const SecretKey&, size_t i) const;
        unique_ptr<Nizk_DLEQ> decShare(const PublicKey&, const SecretKey&, size_t i) const;
        unique_ptr<const Mpz> rec(vector<unique_ptr<const Share>>& Ais) const;

        //Reconstruction Verification
        bool verifyDec(const Share& Ai, const PublicKey& pki, unique_ptr<Nizk_DLEQ> pf, size_t i) const;
        /**@}*/

        private:
        void computeFixedPolyPoints(vector<unique_ptr<Mpz>>& vis, const size_t& n, const Mpz& q);
    };
}

#endif /* QCLPVSS__ */
