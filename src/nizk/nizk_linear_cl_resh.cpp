#include "nizk_linear_cl_resh.hpp"

using namespace NIZK;

NizkLinCLResh::NizkLinCLResh(HashAlgo& hash, RandGen& rand, const CL_HSMqk& cl,
    const SecLevel& seclevel)
    : NizkLinCL(hash, rand, cl, seclevel) {}