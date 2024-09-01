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
    CryptoContext<DCRTPoly> cryptoContext; //TODO:Pass by reference
    bool isVect = false;
    bool isE2DM = false;

    public:
    //constructing from a ctxt
    cipherTensor(ctxt inputCtxtVect, unsigned int dimensionSize, CryptoContext<DCRTPoly> &cryptoContext);

    //constructing from a internalTensor
    cipherTensor(internalTensor inputMatrix, CryptoContext<DCRTPoly> &cryptoContext, bool makeDiag, KeyPair<DCRTPoly> keypair);

    ctxt getRow(unsigned int rowNum);

    std::vector<ctxt> getCipher();

    ctxt getRowConcat();

    ctxt encodeAndEncrypt(vct vect, KeyPair<DCRTPoly> keypair);

    static cipherTensor encMtxVectMult(cipherTensor matrix, cipherTensor vect, CryptoContext<DCRTPoly> cryptoContext);

    static cipherTensor encMtxPlainVectMult(cipherTensor matrix, internalTensor vect, CryptoContext<DCRTPoly> cryptoContext);

    static cipherTensor plainMtxEncVectMult(internalTensor matrix, cipherTensor vect, CryptoContext<DCRTPoly> cryptoContext);

    static ctxt sigmaTransform(cipherTensor matrix, int dimension, CryptoContext<DCRTPoly> cryptoContext, KeyPair<DCRTPoly> keys);

    static ctxt tauTransform(cipherTensor matrix, unsigned int dimension, CryptoContext<DCRTPoly> cryptoContext, KeyPair<DCRTPoly> keys);

    static std::vector<ctxt> phiTransform(ctxt sigmaResult, unsigned int dimension, CryptoContext<DCRTPoly> cryptoContext, KeyPair<DCRTPoly> keys);

    static std::vector<ctxt> psiTransform(ctxt tauResult, unsigned int dimension, CryptoContext<DCRTPoly> cryptoContext, KeyPair<DCRTPoly> keys);

    void decryptAndPrint(KeyPair<DCRTPoly> keypair);

    static cipherTensor matrixMult(cipherTensor matrix1, cipherTensor matrix2, unsigned int dimension, CryptoContext<DCRTPoly> cryptoContex, KeyPair<DCRTPoly> keys);


};

#endif