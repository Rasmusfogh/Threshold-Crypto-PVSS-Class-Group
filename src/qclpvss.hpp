#ifndef QCLPVSS__
#define QCLPVSS__

#include <iostream>
#include "utils/qclpvss_utils.hpp"
#include "utils/sss.hpp"
#include "nizk/nizkpok_dl.hpp"

using namespace BICYCL;
using namespace OpenSSL;
using namespace UTILS;
using namespace NIZKPOK_DL_;
using namespace std;
using namespace SSS_;

namespace QCLPVSS_
{   
    class QCLPVSS 
    {
        public:

        CL_HSMqk cl_hsmqk_;
        SecLevel seclevel_;

        /** number of parties. n + k <= q*/
        const size_t n_;
        /** privacy threshold. k + t <= n*/
        const size_t t_;

        const Mpz q_;

        HashAlgo & hash_;
        RandGen & randgen_;

        public:

        /** Constructor is Setup(). @p q: prime and > 2^seclevel @p k: size of secret, @p t: privacy threshhold, @p n: number of parties  */
        QCLPVSS (SecLevel, HashAlgo &, RandGen&, Mpz &q, const size_t k,
             const size_t n, const size_t t, bool compact_variant);


        /** @name Cryptographic functionalities 
         * @{
         * */ 

        //Setup
        SecretKey keyGen(RandGen &randgen) const;
        PublicKey keyGen(const SecretKey &sk) const;
        NizkPoK_DL keyGen(RandGen &randgen, const PublicKey &pk, const SecretKey & sk) const;
        bool verifyKey(SecretKey &sk, PublicKey &pk, NizkPoK_DL &pf) const;

        //Distribution
        const vector<Share>& dist(RandGen &randgen, const Mpz &s) const;
        void dist(RandGen&, const PublicKey&, const Share&) const;

        //Distribution Verification
        void verifySharing();

        //Reconstruction
        void decShare();
        void rec();

        //Reconstruction Verification
        void verifyDec();
        /**@}*/

        const SecLevel & lambda() const;
    };
}

#endif /* QCLPVSS__ */
