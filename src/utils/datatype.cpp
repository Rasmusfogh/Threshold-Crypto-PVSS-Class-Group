#include <datatype.hpp>

using namespace DATATYPE;

EncShares::EncShares(size_t n) : Bs(n) {}

EncSharesExt::EncSharesExt(size_t n, const ECGroup& ec_group_) 
    : Bs_(n), Ds_(n) 
    {
    //Ds_.reserve(n);
    for(size_t i = 0; i < n; i++)
        Ds_[i] = unique_ptr<ECPoint>(new ECPoint(ec_group_));
    }

DecShare::DecShare() {}
