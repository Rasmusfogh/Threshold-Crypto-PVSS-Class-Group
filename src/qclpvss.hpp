#ifndef QCLPVSS__
#define QCLPVSS__

#include "datatype.hpp"
#include "nizk_dl.hpp"
#include "nizk_sh.hpp"
#include "qclpvss_utils.hpp"
#include "sss.hpp"
#include <iostream>
#include <memory>

using namespace BICYCL;
using namespace OpenSSL;
using namespace NIZK;
using namespace std;
using namespace SSS_;
using namespace DATATYPE;
using namespace UTILS;

namespace QCLPVSS_ {
    class QCLPVSS : public CL_HSMqk {
      public:
        const SecLevel& seclevel_;
        const size_t k_;
        /** number of parties. n + k <= q*/
        const size_t n_;
        /** privacy threshold. k + t <= n*/
        const size_t t_;
        const Mpz& q_;

        // SCRAPE vi's for i \in [1 ... n]
        vector<Mpz> Vis_;

        // Overwrite aliases from base class
        using SecretKey = UTILS::SecretKey;
        using PublicKey = UTILS::PublicKey;

      protected:
        SSS sss_;
        HashAlgo& hash_;
        RandGen& randgen_;

      public:
        /** Constructor is Setup(). @p q: prime and > 2^seclevel @p k: size of
         * secret, @p t: privacy threshhold, @p n: number of parties  */
        QCLPVSS(const SecLevel&, HashAlgo&, RandGen&, const Mpz& q,
            const size_t k, const size_t n, const size_t t);

        /** @name Cryptographic functionalities
         * @{
         * */

        // Setup
        unique_ptr<const SecretKey> keyGen(RandGen&) const;
        unique_ptr<const PublicKey> keyGen(const SecretKey&) const;
        unique_ptr<NizkDL> keyGen(const PublicKey&, const SecretKey&) const;
        bool verifyKey(const PublicKey&, const NizkDL&) const;

        // Distribution
        unique_ptr<EncShares> dist(const Mpz& secret,
            vector<unique_ptr<const PublicKey>>&) const;

        // Distribution Verification
        bool verifySharing(const EncShares&,
            vector<unique_ptr<const PublicKey>>&) const;

        // Reconstruction
        unique_ptr<DecShare> decShare(const PublicKey&, const SecretKey&,
            const QFI& R, const QFI& B, size_t i) const;
        unique_ptr<const Mpz> rec(vector<unique_ptr<const Share>>& Ais) const;

        // Reconstruction Verification
        bool verifyDec(const DecShare&, const PublicKey&, const QFI& R,
            const QFI& B) const;
        /**@}*/

      protected:
        unique_ptr<vector<unique_ptr<const Share>>> createShares(
            const Mpz& secret) const;

        unique_ptr<EncShares> EncryptShares(vector<unique_ptr<const Share>>&,
            const vector<unique_ptr<const PublicKey>>&) const;

        void computeSHNizk(vector<unique_ptr<const PublicKey>>&,
            EncShares&) const;

        // offset is distance from 0 from which v_i starts. If v_i is computed
        // for i \in [1 ... n], then the offset is 1. If v_i is computed
        // for i \in [0 ... n], then the offset is 0
        void computeSCRAPEcoeffs(vector<Mpz>& vis, const size_t n,
            const size_t offset, const Mpz& q);
    };
}    // namespace QCLPVSS_

#endif /* QCLPVSS__ */
