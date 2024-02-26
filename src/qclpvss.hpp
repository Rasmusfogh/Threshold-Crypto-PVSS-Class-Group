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

        CL_HSMqk cl_hsmqk_;
        SecLevel& seclevel_;

        /** number of parties. n + k <= q*/
        const size_t n_;
        /** privacy threshold. k + t <= n*/
        const size_t t_;

        const Mpz& q_;

        HashAlgo & hash_;
        RandGen & randgen_;

        //Public parameters in dist
        unique_ptr<QFI> R_;
        vector<unique_ptr<QFI>> Bs_;


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
        unique_ptr<NizkPoK_DL> keyGen(RandGen&, const PublicKey&, const SecretKey&) const;
        bool verifyKey(const PublicKey&, unique_ptr<NizkPoK_DL>) const;

        //Distribution
        unique_ptr<vector<unique_ptr<const Share>>> dist(RandGen&, const Mpz &s) const;
        void dist(RandGen&, vector<unique_ptr<const PublicKey>>&, vector<unique_ptr<const Share>>&) const;

        //Distribution Verification
        void verifySharing();

        //Reconstruction
        void decShare();
        void rec();

        //Reconstruction Verification
        void verifyDec();
        /**@}*/
    };
}

#endif /* QCLPVSS__ */
