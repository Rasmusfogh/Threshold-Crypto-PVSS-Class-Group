#ifndef QCLPVSS__
#define QCLPVSS__

#include "qclpvss_utils.hpp"
#include "nizk/nizkpok_dl.hpp"

using namespace BICYCL;
using namespace OpenSSL;
using namespace UTILS;
using namespace NIZKPOK_DL_;

namespace QCLPVSS_
{   
    class QCLPVSS 
    {
        public:

        CL_HSMqk cl_hsmqk_;
        SecLevel seclevel_;

        /** number of parties. n + k <= q*/
        size_t n_;
        /** privacy threshold. k + t <= n*/
        size_t t_;

        Mpz q_;

        /** random number functions to generate random alphas [1...n] and betas [1...k] */
        /** OBS! Make sure default seed is not fixed, otherwise set seed somewhere*/
        RandGen alphas_;
        RandGen betas_;

        HashAlgo & hash_;

        public:

        /** Constructor is Setup(). @p q: prime and > 2^seclevel @p k: size of secret, @p t: privacy threshhold, @p n: number of parties  */
        QCLPVSS (SecLevel seclevel, HashAlgo &hash, RandGen &alphas, RandGen &betas, 
        Mpz &q, size_t k, size_t n, size_t t, bool compact_variant);


        /** @name Cryptographic functionalities 
         * @{
         * */ 

        //Setup
        SecretKey keyGen(RandGen &randgen) const;
        PublicKey keyGen(const SecretKey &sk) const;
        NizkPoK_DL keyGen(RandGen &randgen, const PublicKey &pk, const SecretKey & sk) const;
        bool verifyKey(SecretKey &sk, PublicKey &pk, NizkPoK_DL &pf) const;

        //Distribution
        void dist(RandGen &randgen, const PublicKey &pk, const Mpz &s) const;

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
