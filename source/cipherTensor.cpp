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
    this->cryptoContext = cryptoContext;
}

//constructing from a internalTensor
cipherTensor::cipherTensor(internalTensor inputMatrix, CryptoContext<DCRTPoly> inputCryptoContext, bool makeDiag, KeyPair<DCRTPoly> keypair) {
    this->cryptoContext = inputCryptoContext;
    if (inputMatrix.isVector()) {
        this->isVect = true;
        this->cipher.push_back(encodeAndEncrypt((inputMatrix.getMatrix())[0], keypair));
        this->dimensionSize = inputMatrix.getColSize();
    } else {
        mtx diagVectors;
        if (makeDiag) {
            diagVectors = inputMatrix.getDiagonalVectors();
        } else {
            diagVectors = inputMatrix.getMatrix();
        }
        
        for (auto v : diagVectors) {
            ctxt cipherVect = encodeAndEncrypt(v, keypair);
            this->cipher.push_back(cipherVect);
        }
        this->dimensionSize = inputMatrix.getColSize();
        this->rowConcat = encodeAndEncrypt(inputMatrix.rowConcat, keypair);
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
    ctxt result = this->cryptoContext->Encrypt(keypair.publicKey, ptxt);
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


//Algo for generating sigma transform matrix
std::vector<dbl> generateSigmaMatrixDiag(int diagonalNum, unsigned int dimension) {
    unsigned int size = dimension * dimension;
    std::vector<dbl> transformDiag = std::vector<dbl>(size);
    if (diagonalNum >= 0) {
        for (int pos = 0; pos < size; pos++) {
            int checkFormula = pos - dimension * diagonalNum;
            if (checkFormula >= 0 && checkFormula < (dimension - diagonalNum)) {
                transformDiag[pos] = 1;
            } else {
                transformDiag[pos] = 0;
            }
        }
    } else {
        for (int pos = 0; pos < size; pos++) {
            int checkFormula = pos - (dimension + diagonalNum) * dimension;
            if (checkFormula >= -diagonalNum && checkFormula < dimension) {
                transformDiag[pos] = 1;
            } else {
                transformDiag[pos] = 0;
            }
        }
    }
    return transformDiag;
}

//Algo for generating tau transform matrix
std::vector<dbl> generateTauMatrixDiag(int diagonalNum, unsigned int dimension) {
    unsigned int size = dimension * dimension;
    std::vector<dbl> transformDiag = std::vector<dbl>(size, 0);
    for (int i = 0; i < dimension; i++) {
        transformDiag[diagonalNum + dimension*i] = 1;
    }
    return transformDiag;
}

//Algo for generating rowshift transform matrix
std::vector<dbl> generateRowShiftMatrixDiag(int diagonalNum, unsigned int dimension) {
    unsigned int size = dimension * dimension;
    std::vector<dbl> transformDiag;
    if (diagonalNum == 1) {
        transformDiag = std::vector<dbl>(size, 1);
    } else {
        transformDiag = std::vector<dbl>(size, 0);
    }
    return transformDiag;
}

//Algo for generating colshift transform matrix
std::vector<dbl> generateColShiftMatrixDiag(int diagonalNum, unsigned int dimension) {
    unsigned int size = dimension * dimension;
    std::vector<dbl> transformDiag = std::vector<dbl>(size);
    for (int pos = 0; pos < size; pos++) {
        if (pos%dimension >= 0 && pos%dimension < (dimension - diagonalNum)) {
            transformDiag[pos] = 1;
        } else if (pos%dimension < dimension && pos%dimension > (dimension - diagonalNum)) {
            transformDiag[pos] = 1;
        } else {
            transformDiag[pos] = 0;
        }
    }
    return transformDiag;
}

cipherTensor sigmaTranform(cipherTensor matrix, unsigned int dimension) {

}
 