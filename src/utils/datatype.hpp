#ifndef DATATYPE_HPP__
#define DATATYPE_HPP__

#include "nizk_dl.hpp"
#include "nizk_resh.hpp"
#include "nizk_sh.hpp"
#include "nizk_sh_ext.hpp"
#include "sss.hpp"
#include <bicycl.hpp>
#include <memory>

using namespace BICYCL;
using namespace std;
using namespace NIZK;
using namespace SSS_;

namespace DATATYPE {

    class BaseEncShares {
      public:
        Mpz r_;
        QFI R_;
        unique_ptr<vector<shared_ptr<QFI>>> Bs_;
    };

    class EncShares : public BaseEncShares {
      public:
        unique_ptr<NizkSH> pf_;

        EncShares(size_t n);
    };

    class EncSharesExt : public BaseEncShares {
      public:
        unique_ptr<vector<shared_ptr<ECPoint>>> Ds_;
        unique_ptr<NizkExtSH> pf_;

        EncSharesExt(size_t n, BaseEncShares&);
        EncSharesExt(BaseEncShares&, unique_ptr<vector<shared_ptr<ECPoint>>>,
            unique_ptr<NizkExtSH>);
    };

    class EncSharesResh : public BaseEncShares {
      public:
        unique_ptr<NizkResh> pf_;

        EncSharesResh(BaseEncShares&);
        EncSharesResh(BaseEncShares&, unique_ptr<NizkResh>);
    };

    class DecShare {
      public:
        unique_ptr<const Share> sh_;
        unique_ptr<NizkDLEQ> pf_;

        DecShare();
    };

}    // namespace DATATYPE

#endif