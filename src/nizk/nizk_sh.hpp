#ifndef NIZK_SH_HPP__
#define NIZK_SH_HPP__

#include "qclpvss_utils.hpp"
#include "bicycl.hpp"
#include "nizk/nizk_dleq.hpp"

using namespace UTILS;
using namespace BICYCL;
using namespace OpenSSL;
using namespace std;

namespace NIZK
{
    //Forward declaration
    class Nizk_DLEQ;

    class Nizk_SH {

        protected:

        const Mpz& q_;
        HashAlgo& h_;
        RandGen& rand_;
        const CL_HSMqk& CL_;
        const size_t n_, t_;
        unique_ptr<Nizk_DLEQ> pf_;
        
        size_t degree_;

        public:

        Nizk_SH(HashAlgo&, RandGen&, const CL_HSMqk&, vector<unique_ptr<const PublicKey>>&, 
                const vector<unique_ptr<QFI>>& Bs, const QFI& R, const size_t& n, const size_t& t, const Mpz& q,
                const Mpz& r, const vector<unique_ptr<Mpz>>& Vis);

        bool verify(vector<unique_ptr<const PublicKey>>&, const vector<unique_ptr<QFI>>& Bs, 
                const QFI& R, const vector<unique_ptr<Mpz>>& Vis);

        private:

        void initSeed(Mpz& seed, vector<unique_ptr<const PublicKey>>& pks, const vector<unique_ptr<QFI>>& Bs,
                const QFI& R, const QFI&h, const QFI& f) const;

        void computeUV(QFI& U_ref, QFI& V_ref, const vector<unique_ptr<Mpz>>& Vis, 
                vector<unique_ptr<const PublicKey>>& pks, const vector<unique_ptr<QFI>>& Bs, const vector<Mpz>& coeffs) const;

        void generateCoefficients(RandGen&, Mpz& seed, vector<Mpz>& coeff) const;
    };
}

#endif