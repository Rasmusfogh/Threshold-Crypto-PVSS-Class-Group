#ifndef QCLPVSS__
#define QCLPVSS__

#include <iostream>
#include <memory>
#include <qclpvss_utils.hpp>
#include <sss.hpp>
#include <nizkpok_dl.hpp>
#include <nizk_sh.hpp>
#include <datatype.hpp>

using namespace BICYCL;
using namespace OpenSSL;
using namespace UTILS;
using namespace NIZK;
using namespace std;
using namespace SSS_;
using namespace DATATYPE;

namespace QCLPVSS_
{   
    class QCLPVSS 
    {
        public:

        SSS sss_;
        CL_HSMqk CL_;
        SecLevel& seclevel_;

        const size_t k_;
        /** number of parties. n + k <= q*/
        const size_t n_;
        /** privacy threshold. k + t <= n*/
        const size_t t_;

        const Mpz& q_;

        //fixed points used to evaluate the sharing polynomial for the sharing proof
        vector<unique_ptr<Mpz>> Vis_;

        HashAlgo& hash_;
        RandGen& randgen_;

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
        bool verifyKey(const PublicKey&, const NizkPoK_DL&) const;

        //Distribution
        unique_ptr<vector<unique_ptr<const Share>>> dist(const Mpz &secret) const;
        unique_ptr<EncShares> dist(vector<unique_ptr<const PublicKey>>&, vector<unique_ptr<const Share>>&) const;

        //Distribution Verification
        bool verifySharing(const EncShares&, vector<unique_ptr<const PublicKey>>&) const;

        //Reconstruction
        unique_ptr<DecShare> decShare(const PublicKey&, const SecretKey&, const QFI& R, const QFI& B, size_t i) const;
        unique_ptr<const Mpz> rec(vector<unique_ptr<const Share>>& Ais) const;

        //Reconstruction Verification
        bool verifyDec(const DecShare&, const PublicKey& pki, const QFI& R, const QFI& B) const;
        /**@}*/

        private:
        void computeFixedPolyPoints(vector<unique_ptr<Mpz>>& vis, const size_t& n, const Mpz& q);
    };
}

#endif /* QCLPVSS__ */
