``ZkPoK{ (R1, R2): h1 = sha256(R1) and h2 = sha256(R2) and R1 = R2 xor X }``

on my computer (Intel(R) Core(TM) i7-3770S CPU @ 3.10GHz):

* **key generation time**: 11.6652s
* **proof generation time**: 3.0603s
* **verification time**: 0.0281s
* **proof size**: 287 bytes
* **proving key size**: ~12.85 megabytes
* **verifying key size**: ~574 bytes
* **R1CS constraints**: 57380 (54560 sha256-related)


howto:

``./get-libsnark && make && ./test``