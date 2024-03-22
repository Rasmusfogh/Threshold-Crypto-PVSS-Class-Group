#include <secp256k1_wrapper.hpp>
#include <../../include/secp256k1/utils.h>
#include <iostream>
#include <assert.h>

using namespace EC;
using namespace std;

Secp256k1::Secp256k1()
{
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    unsigned char randomize[32];

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

const Mpz Secp256k1::exponent(const Mpz& e)
{
    mpz_export(buffer, nullptr, 1, 1, 0, 0, e.mpz_);

    secp256k1_pubkey pubkey;
    bool success = secp256k1_ec_pubkey_create(ctx, &pubkey, buffer);
    assert(success);

    unsigned char res[33];

    size_t len = sizeof(res);
    secp256k1_ec_pubkey_serialize(ctx, res, &len, &pubkey, SECP256K1_EC_COMPRESSED);

    //skipping first byte as it is the sign
    return Mpz(vector<unsigned char>(res + 1, res + len));
}


Secp256k1::~Secp256k1()
{
    secp256k1_context_destroy(ctx);
}