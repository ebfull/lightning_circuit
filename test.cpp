#include <stdlib.h>
#include <iostream>

#include "snark.hpp"
#include "sha256.h"

using namespace libsnark;
using namespace std;

void convertBytesToVector(const unsigned char* bytes, std::vector<bool>& v) {
    int numBytes = v.size() / 8;
    unsigned char c;
    for(int i = 0; i < numBytes; i++) {
        c = bytes[i];

        for(int j = 0; j < 8; j++) {
            v.at((i*8)+j) = ((c >> (7-j)) & 1);
        }
    }
}

bool test(r1cs_ppzksnark_keypair<default_r1cs_ppzksnark_pp>& keypair,
          bool use_and_instead_of_xor=false,
          bool swap_r1=false,
          bool omit_proper_padding=false,
          bool goofy_verification_inputs=false
    ) {

    // Initialize bit_vectors for all of the variables involved.
    std::vector<bool> h1_bv(256);
    std::vector<bool> h2_bv(256);
    std::vector<bool> x_bv(256);
    std::vector<bool> r1_bv(256);
    std::vector<bool> r2_bv(256);

    {
        // These preimages don't have consequences in the circuit.
        // R1, R2 and X are just 256 bits long.
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

        if (use_and_instead_of_xor) {
            // [test] Use bit_and instead of bit_xor to simulate
            // R1 != R2 ^ X
            std::transform(std::begin(r2), std::end(r2),
                std::begin(x),
                std::begin(r1),
                std::bit_and<unsigned char>());
        } else {
            std::transform(std::begin(r2), std::end(r2),
                std::begin(x),
                std::begin(r1),
                std::bit_xor<unsigned char>());
        }

        {
            SHA256_CTX_mod ctx256;
            sha256_init(&ctx256);
            sha256_update(&ctx256, r1, 32);
            if (!omit_proper_padding) {
                // [test] Omit the length padding to see if
                // our SHA256 hash is properly working and that
                // the padding works.
                sha256_length_padding(&ctx256);
            }
            sha256_final_no_padding(&ctx256, h1);
        }

        {
            SHA256_CTX_mod ctx256;
            sha256_init(&ctx256);
            sha256_update(&ctx256, r2, 32);
            if (!omit_proper_padding) {
                // [test] like above
                sha256_length_padding(&ctx256);
            }
            sha256_final_no_padding(&ctx256, h2);
        }

        convertBytesToVector(h1, h1_bv);
        convertBytesToVector(h2, h2_bv);
        convertBytesToVector(x, x_bv);

        if (swap_r1) {
            // [test] ensure that the relationship between
            // r1 and r2 is preserved by swapping them and
            // expecting it to fail
            convertBytesToVector(r1, r2_bv);
            convertBytesToVector(r2, r1_bv);
        } else {
            convertBytesToVector(r1, r1_bv);
            convertBytesToVector(r2, r2_bv);
        }
    }

    cout << "Trying to generate proof..." << endl;
    auto proof = generate_proof<default_r1cs_ppzksnark_pp>(keypair.pk, h1_bv, h2_bv, x_bv, r1_bv, r2_bv);
    cout << "Proof generated!" << endl;

    if (!proof) {
        return false;
    } else {
        if (goofy_verification_inputs) {
            // [test] if we generated the proof but try to validate
            // with bogus inputs it shouldn't let us
            return verify_proof(keypair.vk, *proof, h2_bv, h1_bv, x_bv);
        } else {
            // verification should not fail if the proof is generated!
            assert(verify_proof(keypair.vk, *proof, h1_bv, h2_bv, x_bv));
            return true;
        }
    }
}

int main()
{
    // Initialize the curve parameters.
    default_r1cs_ppzksnark_pp::init_public_params();
    // Generate the verifying/proving keys. (This is trusted setup!)
    auto keypair = generate_keypair<default_r1cs_ppzksnark_pp>();

    // Run test vectors.
    assert(test(keypair));
    assert(!test(keypair, true));
    assert(!test(keypair, false, true));
    assert(!test(keypair, false, false, true));
    assert(!test(keypair, false, false, false, true));
}