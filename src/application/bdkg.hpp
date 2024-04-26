#ifndef BDKG_HPP__
#define BDKG_HPP__

#include "qclpvss.hpp"

using namespace QCLPVSS_;
using namespace NIZK;

namespace Application {
    class BDKG : private QCLPVSS {
      protected:
        const ECGroup& ec_group_;

        vector<Mpz> lambdas_;

      public:
        vector<unique_ptr<const SecretKey>> sks_;
        vector<unique_ptr<const PublicKey>> pks_;
        vector<unique_ptr<NizkDL>> keygen_pf_;

      public:
        BDKG(SecLevel&, HashAlgo&, RandGen&, const ECGroup&, Mpz& q,
            const size_t k, const size_t n, const size_t t);

        unique_ptr<EncSharesExt> dist(const Mpz& s,
            vector<unique_ptr<const PublicKey>>&) const;

        /** @name Global/Private output helper functions
         * @{
         * */

        // Compute global public key tpk
        unique_ptr<ECPoint> compute_tpk(const vector<ECPoint>& tpks) const;

        // Compute partial secret key i
        const Mpz compute_tsk_i(const vector<shared_ptr<QFI>>& Bs,
            const vector<QFI>& Rs, const SecretKey& ski) const;

        /**@}*/

        /** @name Verification helper functions to ensure correct computation of
         * partial keypairs and global keypair. Not part of DKG.
         * @{
         * */

        // Compute global secret key tsk
        Mpz compute_tsk(const vector<Mpz>& tsks) const;

        // Verify relation between key pair tsk_i and tpk_i
        bool verify_partial_keypairs(const vector<Mpz>& tsks,
            const vector<ECPoint>& tpks) const;

        // Verify globl key pair
        bool verify_global_keypair(const Mpz& tsk, const ECPoint& tpk) const;
        /**@}*/

      private:
        /* Pre-computation of lamdas */
        void compute_lambdas(vector<Mpz>& lambdas, const size_t n,
            const size_t t, const Mpz& q);
    };
}    // namespace Application

#endif
