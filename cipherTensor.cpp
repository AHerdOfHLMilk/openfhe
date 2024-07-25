#include "cipherTensor.h"


using namespace lbcrypto;

typedef Ciphertext<DCRTPoly> ctxt;

//External structure for taking in the cryptocontext and encoding and encryption
//--------------------------------------------------------------------------------------------------------------------------------------------------
//constructing from a ctxt
cipherTensor::cipherTensor(ctxt inputCtxtVect, unsigned int dimensionSize, CryptoContext<DCRTPoly> cryptoContext) {
    this->isVect = true;
    this->cipher.push_back(inputCtxtVect);
    this->dimensionSize = dimensionSize;
}

//constructing from a internalTensor
cipherTensor::cipherTensor(internalTensor inputMatrix, CryptoContext<DCRTPoly> cryptoContext, bool makeDiag, KeyPair<DCRTPoly> keypair) {
    if (inputMatrix.internalTensor::isVector()) {
        this->isVect = true;
        this->cipher.push_back(encodeAndEncrypt((inputMatrix.internalTensor::getMatrix())[0], keypair));
        this->dimensionSize = inputMatrix.internalTensor::getColSize();
    } else {
        mtx diagVectors;
        if (makeDiag) {
            diagVectors = inputMatrix.getDiagonalVectors();
        } else {
            diagVectors = inputMatrix.getMatrix();
        }
        
        for (auto v : diagVectors) {
            this->cipher.push_back(encodeAndEncrypt(v, keypair));
        }
        this->dimensionSize = inputMatrix.getColSize();
    }
}

ctxt cipherTensor::getRow(unsigned int rowNum) {
    return cipher[rowNum];
}

std::vector<ctxt> cipherTensor::getCipher() {
    return cipher;
}

ctxt cipherTensor::encodeAndEncrypt(vct vect, KeyPair<DCRTPoly> keypair) {
    Plaintext ptxt = this->cryptoContext->MakeCKKSPackedPlaintext(vect);
    ctxt result = this->cryptoContext->Encrypt(keypair.secretKey, ptxt);
    return result;
}

cipherTensor cipherTensor::encMtxVectMult(cipherTensor matrix, cipherTensor vect, CryptoContext<DCRTPoly> cryptoContext) {
    unsigned int dimension = vect.dimensionSize;
    ctxt sum = cryptoContext->EvalMult(matrix.getRow(0), vect.getRow(0));
    for (int rotation = 1; rotation < dimension; rotation++) {
        ctxt multipliedResult = cryptoContext->EvalMult(matrix.getRow(rotation), vect.getRow(rotation));
        sum = cryptoContext->EvalAdd(sum, multipliedResult);
    }
    return cipherTensor(sum, dimension, cryptoContext);
}

cipherTensor cipherTensor::encMtxPlainVectMult(cipherTensor matrix, internalTensor vect, CryptoContext<DCRTPoly> cryptoContext) {
    unsigned int dimension = vect.getColSize();
    ctxt sum = cryptoContext->EvalMult(matrix.getRow(0), cryptoContext->MakeCKKSPackedPlaintext(vect.getRow(0)));
    for (int rotation = 1; rotation < dimension; rotation++) {
        ctxt multipliedResult = cryptoContext->EvalMult(matrix.getRow(rotation), cryptoContext->MakeCKKSPackedPlaintext(vect.getRow(rotation)));
        sum = cryptoContext->EvalAdd(sum, multipliedResult);
    }
    return cipherTensor(sum, dimension, cryptoContext);
}

cipherTensor cipherTensor::plainMtxEncVectMult(internalTensor matrix, cipherTensor vect, CryptoContext<DCRTPoly> cryptoContext) {
    unsigned int dimension = vect.dimensionSize;
    ctxt sum = cryptoContext->EvalMult(cryptoContext->MakeCKKSPackedPlaintext(matrix.getRow(0)), vect.getRow(0));
    for (int rotation = 1; rotation < dimension; rotation++) {
        ctxt multipliedResult = cryptoContext->EvalMult(cryptoContext->MakeCKKSPackedPlaintext(matrix.getRow(rotation)), vect.getRow(rotation));
        sum = cryptoContext->EvalAdd(sum, multipliedResult);
    }
    return cipherTensor(sum, dimension, cryptoContext);
}

void cipherTensor::decryptAndPrint(KeyPair<DCRTPoly> keypair) {
    for (auto result : this->cipher) {
        Plaintext toPrint;
        this->cryptoContext->Decrypt(keypair.secretKey, result, &toPrint);
        std::cout << toPrint << std::endl;
    }
}

int main() {
    return -1;
}