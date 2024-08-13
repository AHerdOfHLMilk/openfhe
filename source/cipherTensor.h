#ifndef CIPHERTENSOR   // To make sure you don't declare the function more than once by including the header multiple times.
#define CIPHERTENSOR

#include <algorithm>
#include <string>
#include <omp.h>
#include "internalTensor.h"
#include "openfhe.h"

using namespace lbcrypto;

typedef Ciphertext<DCRTPoly> ctxt;

class cipherTensor { //can jus convert the various storing of forms into jus a flag bcos will only ever be 1 form at a time
    private:
    unsigned int dimensionSize;
    std::vector<ctxt> cipher = {}; //in diagonal packing form
    ctxt rowConcat;
    CryptoContext<DCRTPoly> cryptoContext;
    bool isVect = false;

    public:
    //constructing from a ctxt
    cipherTensor(ctxt inputCtxtVect, unsigned int dimensionSize, CryptoContext<DCRTPoly> cryptoContext);

    //constructing from a internalTensor
    cipherTensor(internalTensor inputMatrix, CryptoContext<DCRTPoly> cryptoContext, bool makeDiag, KeyPair<DCRTPoly> keypair);

    ctxt getRow(unsigned int rowNum);

    std::vector<ctxt> getCipher();

    ctxt encodeAndEncrypt(vct vect, KeyPair<DCRTPoly> keypair);

    static cipherTensor encMtxVectMult(cipherTensor matrix, cipherTensor vect, CryptoContext<DCRTPoly> cryptoContext);

    static cipherTensor encMtxPlainVectMult(cipherTensor matrix, internalTensor vect, CryptoContext<DCRTPoly> cryptoContext);

    static cipherTensor plainMtxEncVectMult(internalTensor matrix, cipherTensor vect, CryptoContext<DCRTPoly> cryptoContext);

    void decryptAndPrint(KeyPair<DCRTPoly> keypair);


};

#endif