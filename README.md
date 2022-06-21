# crypto-lab
Golang implementation of cryptographic algorithms 

## 1. common
- matrix: matrix operation mod P
- crt: chinese remainder theorem

## 2. symmetric
- aes

## 3. asymmetric
- bls
- ecies
- paillier
- rsa
- sm2

## 4. hash
- sm3
- Chameleon hash

## 5. advanced
- hd: hierarchical deterministic encryption
- ring_sign: ring signature based on RSA
- linkable_ring_sign: linkable ring signature based on RSA
- he: fully homomorphic encryption
  - bfv
- ss: secret sharing
  - shamir: Shamir's secret sharing
  - blakley: Blakley's secret sharing
  - crt: secret sharing using CRT
- mpc: multi-party computation related algorithms
  - ot: oblivious transfer based on RSA and ECC
  - gc: yao's garbled circuit
  - psi: private set intersection using DH OPRF
