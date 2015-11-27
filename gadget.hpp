#include "libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp"
#include "algebra/fields/field_utils.hpp"

const size_t sha256_digest_len = 256;

/*
computed by:

        unsigned long long bitlen = 256;

        unsigned char padding[32] = {0x80, 0x00, 0x00, 0x00, // 24 bytes of padding
                                     0x00, 0x00, 0x00, 0x00,
                                     0x00, 0x00, 0x00, 0x00,
                                     0x00, 0x00, 0x00, 0x00,
                                     0x00, 0x00, 0x00, 0x00,
                                     0x00, 0x00, 0x00, 0x00,
                                     bitlen >> 56, bitlen >> 48, bitlen >> 40, bitlen >> 32, // message length
                                     bitlen >> 24, bitlen >> 16, bitlen >> 8, bitlen
                                    };

        std::vector<bool> padding_bv(256);

        convertBytesToVector(padding, padding_bv);

        printVector(padding_bv);
*/
bool sha256_padding[256] = {true, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, true, false, false, false, false, false, false, false, false};

using namespace libsnark;

template<typename FieldT>
class l_gadget : public gadget<FieldT> {
public:
    pb_variable_array<FieldT> input_as_field_elements; /* R1CS input */
    pb_variable_array<FieldT> input_as_bits; /* unpacked R1CS input */
    std::shared_ptr<multipacking_gadget<FieldT> > unpack_inputs; /* multipacking gadget */

    std::shared_ptr<digest_variable<FieldT>> h1_var; /* H(R1) */
    std::shared_ptr<digest_variable<FieldT>> h2_var; /* H(R2) */

    std::shared_ptr<digest_variable<FieldT>> x_var; /* X */
    std::shared_ptr<digest_variable<FieldT>> r1_var; /* R1 */
    std::shared_ptr<digest_variable<FieldT>> r2_var; /* R2 */

    std::shared_ptr<block_variable<FieldT>> h_r1_block;
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> h_r1;

    std::shared_ptr<block_variable<FieldT>> h_r2_block;
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> h_r2;

    std::shared_ptr<digest_variable<FieldT>> padding_var; /* SHA256 length padding */


    l_gadget(protoboard<FieldT> &pb);
    void generate_r1cs_constraints();
    void generate_r1cs_witness(const bit_vector &h1,
                               const bit_vector &h2,
                               const bit_vector &x,
                               const bit_vector &r1,
                               const bit_vector &r2
                              );
};

template<typename FieldT>
r1cs_primary_input<FieldT> l_input_map(const bit_vector &h1,
                                             const bit_vector &h2,
                                             const bit_vector &x
                                            );

#include "gadget.tcc"
