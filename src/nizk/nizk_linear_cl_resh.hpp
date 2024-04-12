#ifndef NIZK_LINEAR_CL_RESH_HPP__
#define NIZK_LINEAR_CL_RESH_HPP__

#include "nizk_linear_cl.hpp"
#include <bicycl.hpp>

using namespace BICYCL;
using namespace OpenSSL;

namespace NIZK {
    class NizkLinCLResh : public NizkLinCL {

      public:
        NizkLinCLResh(HashAlgo&, RandGen&, const CL_HSMqk&, const SecLevel&);
    };
}    // namespace NIZK

#endif