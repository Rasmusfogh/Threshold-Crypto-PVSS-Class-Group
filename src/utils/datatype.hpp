#ifndef DATATYPE_HPP__
#define DATATYPE_HPP__

#include <bicycl.hpp>
#include <memory>
#include <nizk_sh.hpp>
#include <sss.hpp>

using namespace BICYCL;
using namespace std;
using namespace NIZK;
using namespace SSS_;

namespace DATATYPE
{
    class EncShares
    {
        public:
            QFI R;
            vector<QFI> Bs;
            unique_ptr<Nizk_SH> pf;

            EncShares(size_t n);
    };

    class DecShare
    {
        public:
            unique_ptr<const Share> sh;
            unique_ptr<const Nizk_DLEQ> pf;

            DecShare();
    };
}

#endif