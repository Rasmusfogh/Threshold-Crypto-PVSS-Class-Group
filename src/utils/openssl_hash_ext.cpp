#include "bicycl.hpp"
#include <memory>
#include "qclpvss_utils.hpp"

using namespace BICYCL;
using namespace OpenSSL;
using namespace UTILS;
using namespace std;


template<>
void OpenSSL::HashAlgo::hash(const vector<unique_ptr<QFI>> &v)
{
    for(size_t i = 0; i < v.size(); i++)
        hash (*v[i]);
}

template<>
void OpenSSL::HashAlgo::hash(const vector<unique_ptr<const PublicKey>>& v)
{
    for(size_t i = 0; i < v.size(); i++)
        hash (v[i]->get());
}

template<>
void OpenSSL::HashAlgo::hash(const vector<QFI> &v)
{
    for(size_t i = 0; i < v.size(); i++)
        hash (v[i]);
}