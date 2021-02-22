# Homomorphic encryption 
Broadly speaking, homomorphic encryptions include partially homomorphic encryption and fully homomorphic encryption. 
Partially homomorphic encryption schemes like RSA and Paillier are implemented in [asymmetric](../../asymmetric) directory.

There are several open-source FHE projects, like Lattigo, TFHE, PALISADE... 
We import or wrap these projects to achieve FHE encryption, decryption and evaluation.

## 1. Open-source projects
| 开源库     | 支持算法    |   语言   | 代码库地址 |
| --------- | -------   | -------- | ------ |
| Lattigo   | BFV, CKKS | Go       | https://github.com/lca1/lattigo | 
| TFHE      | GSW       | C++      | https://github.com/tfhe/tfhe | 
| Palisade  | BFV, BGV, GSW, CKKS  | C++  | https://gitlab.com/palisade/palisade-release/-/tree/master |  

We mainly use Lattigo and TFHE.

## 2. BFV
We import `Lattigo` for BFV scheme. 
A plaintext modulus need to be set as a parameter for all operations. 
Plaintext that is greater than modulus would be truncated.

Note: if you have to do homomorphic addition/multiplication, the result should be smaller than modulus. 
Otherwise, you will get an unexpected result.
	
```bash
$ go test .
```

## Reference
HE: https://en.wikipedia.org/wiki/Homomorphic_encryption
