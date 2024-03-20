#ifndef NIZK_SH_EXT_HPP__
#define NIZK_SH_EXT_HPP__

#include <memory>
#include "qclpvss_utils.hpp"
#include "bicycl.hpp"
#include "nizk/nizk_dleq.hpp"
#include <nizk_sh_base.hpp>
#include <sss.hpp>

using namespace UTILS;
using namespace BICYCL;
using namespace OpenSSL;
using namespace std;
using namespace SSS_;

namespace NIZK
{
    //Forward declaration
    class Nizk_DLEQ;

    class Nizk_SH_ext : public virtual Nizk_SH_base<pair<vector<unique_ptr<Share>>, Mpz>,     // p(X), r
                        const vector<unique_ptr<const PublicKey>>,                            // pks
                        const vector<QFI>,                                                    // Bs
                        const vector<Mpz>,                                                    // Ds
                        const QFI>                                                            // R
    {

        protected:
        unique_ptr<Nizk_DLEQ> pf_;
        
        public:
        Nizk_SH_ext(HashAlgo&, RandGen&, const CL_HSMqk&, vector<unique_ptr<const PublicKey>>&, 
            const vector<QFI>& Bs, const QFI& R, const vector<Mpz>& Ds, const size_t& n, const size_t& t, 
            const Mpz& q, const vector<unique_ptr<Mpz>>& Vis);

        virtual void prove(const pair<vector<unique_ptr<Share>>, Mpz>& rd, const vector<unique_ptr<const PublicKey>>&,
            const vector<QFI>& Bs, const vector<Mpz>& Ds, const QFI& R) override; 

        virtual bool verify(const vector<unique_ptr<const PublicKey>>&, const vector<QFI>& Bs, 
            const vector<Mpz>& Ds, const QFI& R) const override;
            

    };
}

#endif