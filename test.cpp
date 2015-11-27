#include <stdlib.h>
#include <iostream>

#include "snark.hpp"
#include "sha256.h"
#include "util.h"

using namespace libsnark;
using namespace std;

int main()
{
    default_r1cs_ppzksnark_pp::init_public_params();
    auto keypair = generate_keypair<default_r1cs_ppzksnark_pp>();

    std::vector<bool> h1_bv(256);
    std::vector<bool> h2_bv(256);
    std::vector<bool> x_bv(256);
    std::vector<bool> r1_bv(256);
    std::vector<bool> r2_bv(256);

    {
        unsigned char preimage_a[5] = { 'S', 'C', 'I', 'P', 'R' };
        unsigned char preimage_b[3] = { 'L', 'A', 'B' };

        unsigned char h1[32];
        unsigned char h2[32];
        unsigned char r1[32];
        unsigned char r2[32];
        unsigned char x[32];

        {
            SHA256_CTX_mod ctx256;
            sha256_init(&ctx256);
            sha256_update(&ctx256, preimage_a, 5);
            sha256_final_no_padding(&ctx256, r2);
        }

        {
            SHA256_CTX_mod ctx256;
            sha256_init(&ctx256);
            sha256_update(&ctx256, preimage_b, 3);
            sha256_final_no_padding(&ctx256, x);
        }

        std::transform(std::begin(r2), std::end(r2),
            std::begin(x),
            std::begin(r1),
            std::bit_xor<unsigned char>());

        {
            SHA256_CTX_mod ctx256;
            sha256_init(&ctx256);
            sha256_update(&ctx256, r1, 32);
            sha256_length_padding(&ctx256);
            sha256_final_no_padding(&ctx256, h1);
        }

        {
            SHA256_CTX_mod ctx256;
            sha256_init(&ctx256);
            sha256_update(&ctx256, r2, 32);
            sha256_length_padding(&ctx256);
            sha256_final_no_padding(&ctx256, h2);
        }

        convertBytesToVector(h1, h1_bv);
        convertBytesToVector(h2, h2_bv);
        convertBytesToVector(x, x_bv);
        convertBytesToVector(r1, r1_bv);
        convertBytesToVector(r2, r2_bv);
    }

    auto proof = generate_proof<default_r1cs_ppzksnark_pp>(keypair.pk, h1_bv, h2_bv, x_bv, r1_bv, r2_bv);

    assert(verify_proof(keypair.vk, proof, h1_bv, h2_bv, x_bv));
}