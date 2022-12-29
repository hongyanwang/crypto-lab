# crypto-lab
Golang implementation of cryptographic algorithms 

## 1. common
- matrix: matrix operation mod P
- crt: chinese remainder theorem
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
