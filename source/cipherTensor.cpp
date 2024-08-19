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
    } else if (inputMatrix.isE2DM) {
        this->isE2DM = true;
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
    }
}

ctxt cipherTensor::getRow(unsigned int rowNum) {
    return cipher[rowNum];
}

std::vector<ctxt> cipherTensor::getCipher() {
    return cipher;
}

ctxt cipherTensor::getRowConcat() {
    return this->cipher[0];
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
    // std::cout << "tau of: " << diagonalNum << std::endl;
    // for (auto elem : transformDiag) {
    //     std::cout << elem << ",";
    // }
    std::cout << std::endl;
    return transformDiag;
}

//Algo for generating first psi transform diagonal
std::vector<dbl> generateFirstphiMatrixDiag(int diagonalNum, unsigned int dimension) {
    unsigned int size = dimension * dimension;
    std::vector<dbl> transformDiag = vct(size, 0);
    for (int i = 0; i < size; i++) {
        if (i%dimension >= 0 && i%dimension < (dimension - diagonalNum)) {
            transformDiag[i] = 1;
        }
    }
    return transformDiag;
}

//Algo for generating psi transform matrix
std::vector<dbl> generateSecondphiMatrixDiag(int diagonalNum, unsigned int dimension) {
    unsigned int size = dimension * dimension;
    std::vector<dbl> transformDiag = vct(size, 0);
    for (int i = 0; i < size; i++) {
        if (i%dimension < dimension && i%dimension >= (dimension - diagonalNum)) {
            transformDiag[i] = 1;
        }
    }
    return transformDiag;

}

//TODO: change to phi and psi

ctxt cipherTensor::sigmaTransform(cipherTensor matrix, int dimension, CryptoContext<DCRTPoly> cryptoContextInput, KeyPair<DCRTPoly> keys) {
    vct zeroesMask = vct(dimension*dimension, 0);
    Plaintext zeroesMaskPT = cryptoContextInput->MakeCKKSPackedPlaintext(zeroesMask);
    ctxt sum = matrix.getRowConcat();
    sum = cryptoContextInput->EvalMult(sum, zeroesMaskPT);
    for (int k = -dimension+1; k < dimension; k++) {
        ctxt tempRotate = cryptoContextInput->EvalRotate(matrix.getRowConcat(), k);
        ctxt tempMult = cryptoContextInput->EvalMult(tempRotate, cryptoContextInput->MakeCKKSPackedPlaintext(generateSigmaMatrixDiag(k, dimension)));
        sum = cryptoContextInput->EvalAdd(sum, tempMult);
    }
    return sum;
}

ctxt cipherTensor::tauTransform(cipherTensor matrix, unsigned int dimension, CryptoContext<DCRTPoly> cryptoContextInput, KeyPair<DCRTPoly> keys) {
    vct zeroesMask = vct(dimension*dimension, 0);
    Plaintext zeroesMaskPT = cryptoContextInput->MakeCKKSPackedPlaintext(zeroesMask);
    ctxt sum = matrix.getRowConcat();
    sum = cryptoContextInput->EvalMult(sum, zeroesMaskPT);
    for (int k = 0; k < dimension; k++) {
        ctxt tempRotate = cryptoContextInput->EvalRotate(matrix.getRowConcat(), k * dimension);
        ctxt tempMult = cryptoContextInput->EvalMult(tempRotate, cryptoContextInput->MakeCKKSPackedPlaintext(generateTauMatrixDiag(k, dimension)));
        sum = cryptoContextInput->EvalAdd(sum, tempMult);
        // std::cout << "k = " << k << std::endl;
        // Plaintext toPrint;
        // cryptoContextInput->Decrypt(keys.secretKey, tempRotate, &toPrint);
        // std::cout << toPrint << std::endl;
    }
    return sum;
}

std::vector<ctxt> cipherTensor::phiTransform(ctxt sigmaResult, unsigned int dimension, CryptoContext<DCRTPoly> cryptoContextInput, KeyPair<DCRTPoly> keys) {
    std::vector<ctxt> result = {};
    ctxt sum;
    for (int k = 1; k < dimension; k++) {
        ctxt tempRotate = cryptoContextInput->EvalRotate(sigmaResult, k);
        ctxt tempMult = cryptoContextInput->EvalMult(tempRotate, cryptoContextInput->MakeCKKSPackedPlaintext(generateFirstphiMatrixDiag(k, dimension)));
        ctxt tempRotate2 = cryptoContextInput->EvalRotate(sigmaResult, k-dimension);
        ctxt tempMult2 = cryptoContextInput->EvalMult(tempRotate2, cryptoContextInput->MakeCKKSPackedPlaintext(generateSecondphiMatrixDiag(k, dimension)));
        sum = cryptoContextInput->EvalAdd(tempMult, tempMult2);
        result.push_back(sum);
        std::cout << "k = " << k << std::endl;
        Plaintext toPrint;
        cryptoContextInput->Decrypt(keys.secretKey, tempMult, &toPrint);
        std::cout << toPrint << std::endl;
    }
    return result;
}

std::vector<ctxt> cipherTensor::psiTransform(ctxt tauResult, unsigned int dimension, CryptoContext<DCRTPoly> cryptoContextInput, KeyPair<DCRTPoly> keys) {
    std::vector<ctxt> result = {};
    for (int k = 1; k < dimension; k++) {
        ctxt tempRotate = cryptoContextInput->EvalRotate(tauResult, dimension*k);
        result.push_back(tempRotate);
    }
    return result;
}

cipherTensor cipherTensor::matrixMult(cipherTensor matrix1, cipherTensor matrix2, unsigned int dimension, CryptoContext<DCRTPoly> cryptoContextInput, KeyPair<DCRTPoly> keys) {
    ctxt sigma = sigmaTransform(matrix1, dimension, cryptoContextInput, keys);
    Plaintext toPrint2;
    cryptoContextInput->Decrypt(keys.secretKey, sigma, &toPrint2);
    std::cout << "sigma:" << std::endl << toPrint2 << std::endl;
    ctxt tau = tauTransform(matrix2, dimension, cryptoContextInput, keys);
    Plaintext toPrint3;
    cryptoContextInput->Decrypt(keys.secretKey, tau, &toPrint3);
    std::cout << "tau:" << std::endl << toPrint3 << std::endl;
    std::vector<ctxt> phis = phiTransform(sigma, dimension, cryptoContextInput, keys);
    std::vector<ctxt> psis = psiTransform(tau, dimension, cryptoContextInput, keys);
    ctxt m1m2Mult = cryptoContextInput->EvalMult(sigma, tau);
    std::cout << "phis:" << std::endl; 
    for (ctxt cipher : phis) {
        Plaintext toPrint;
        cryptoContextInput->Decrypt(keys.secretKey, cipher, &toPrint);
        std::cout << toPrint << std::endl;
    }
    std::cout << "psis:" << std::endl; 
    for (ctxt cipher : psis) {
        Plaintext toPrint;
        cryptoContextInput->Decrypt(keys.secretKey, cipher, &toPrint);
        std::cout << toPrint << std::endl;
    }
    for (int k = 0; k < dimension-1; k++) {
        // Plaintext colToPrint;
        // cryptoContextInput->Decrypt(keys.secretKey, phis[k], &colToPrint);
        // std::cout << colToPrint << std::endl;
        ctxt tempMult = cryptoContextInput->EvalMult(phis[k], psis[k]);
        m1m2Mult = cryptoContextInput->EvalAdd(m1m2Mult, tempMult);
    }
    return cipherTensor(m1m2Mult, dimension, cryptoContextInput);
}

///TODO: need a way to when multiply the rowConcat will update the actual matrix too
 