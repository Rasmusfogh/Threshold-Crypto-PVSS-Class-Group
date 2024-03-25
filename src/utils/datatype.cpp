#include <datatype.hpp>

using namespace DATATYPE;

EncShares::EncShares(size_t n) : Bs(n) {}

EncSharesExt::EncSharesExt(size_t n) 
    : Bs_(n), Ds_(n) {}

DecShare::DecShare() {}
