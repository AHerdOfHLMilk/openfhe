#ifndef UTILITIES
#define UTILITIES

#include "cipherTensor.h"
 #include "internalTensor.h"

std::vector<vct> concatenateMatrices(std::vector<std::vector<vct>> matrices);

ctxt vectEncodeAndEncrypt(vct vect, CryptoContext<DCRTPoly> cryptoContext, KeyPair<DCRTPoly> keys);

vct repeatVector(vct vect, unsigned int num);

std::vector<vct> getPackedVector(vct vect, unsigned int numOfMatrices);

std::vector<int> geneerateRotateIndexList(int low, int high);

void printV(std::vector<dbl> v);

void printV(std::vector<int> v);

void printV(std::vector<Plaintext> v);

void printV(std::vector<Ciphertext<DCRTPoly>> v, CryptoContext<DCRTPoly> cc, KeyPair<DCRTPoly> keys);

#endif