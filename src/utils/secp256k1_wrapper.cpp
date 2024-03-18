#include <secp256k1_wrapper.hpp>
#include <../../include/secp256k1/utils.h>
#include <iostream>
#include <assert.h>

using namespace EC;
using namespace std;

Secp256k1::Secp256k1() 
{
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);

    // Randomizing the context is recommended to protect against side-channel leakage 
    if (!fill_random(randomize, sizeof(randomize)))
        throw std::runtime_error ("Failed to generate randomness for secp256k1");

    bool res = secp256k1_context_randomize(ctx, randomize);
    assert(res);
}

const Mpz Secp256k1::randomPoint() const
{
    unsigned char r_[32];
    while (true) {
        fill_random(r_, sizeof(r_));

        if (secp256k1_ec_seckey_verify(ctx, r_))
            break;
    }
    
    return Mpz(vector<unsigned char>(r_, r_ + 32));
}

const Mpz Secp256k1::exponent(const Mpz& e) const
{
    //Round up to nearest byte
    size_t bytes = (e.nbits() + 7 ) / 8;
    unsigned char* buffer = new unsigned char[bytes];

    size_t exportedSize;
    mpz_export(buffer, &exportedSize, 1, 1, 0, 0, e.mpz_);


    delete[] buffer;    
}

Secp256k1::~Secp256k1()
{
    secp256k1_context_destroy(ctx);
}