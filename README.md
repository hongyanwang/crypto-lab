[DOC](https://hongyanwang.github.io/crypto-lab/) | English

[![License](https://img.shields.io/badge/license-Apache%202-blue.svg)](LICENSE)

# crypto-lab
Golang implementation of cryptographic algorithms 

## 1. common
- crt: chinese remainder theorem
- hash_to_point: hash prime filed number to ecc point
- matrix: matrix operation mod P
- polynomial: polynomial operations, including Lagrange interpolation

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
- gc: garbled circuit
  - yao: Yao's garbled circuit
- hd: hierarchical deterministic encryption
- he: fully homomorphic encryption
  - bfv
- ring_sign: ring signature based on RSA
- linkable_ring_sign: linkable ring signature based on RSA
- ot: oblivious transfer based on RSA and ECC
- pir: private information retrieval using homomorphic encryption and Lagrange interpolation
- psi: private set intersection using DH OPRF
- ss: secret sharing
  - shamir: Shamir's secret sharing
  - blakley: Blakley's secret sharing
  - crt: secret sharing using CRT
