#include "libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp"
#include "algebra/fields/field_utils.hpp"

const size_t sha256_digest_len = 256;

using namespace libsnark;

template<typename FieldT>
class example_gadget : public gadget<FieldT> {
public:
    pb_variable_array<FieldT> input_as_field_elements; /* R1CS input */
    pb_variable_array<FieldT> input_as_bits; /* unpacked R1CS input */
    std::shared_ptr<multipacking_gadget<FieldT> > unpack_inputs; /* multipacking gadget */

    std::shared_ptr<digest_variable<FieldT>> h1_var; /* H(R1) */

    /*
    std::shared_ptr<digest_variable<FieldT>> r1_var;
    std::shared_ptr<digest_variable<FieldT>> h1_var;

    std::shared_ptr<block_variable<FieldT>> h_r1_block;
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> h_r1;
    */


    example_gadget(protoboard<FieldT> &pb);
    void generate_r1cs_constraints();
    void generate_r1cs_witness(const bit_vector &h1);
};

template<typename FieldT>
r1cs_primary_input<FieldT> example_input_map(const bit_vector &h1);

#include "gadget.tcc"
