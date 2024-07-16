#include <vector>
#include<algorithm>
#include "openfhe.h"
#include <string>


enum transformMatrixTypes {
    sigma,
    tau,
    rowShift,
    colShift
};

//fill to slotsize for std::vector vector
std::vector<std::complex<double>> getFilledVector(std::vector<std::complex<double>> vect, unsigned int dimension, CryptoContext<DCRTPoly> cryptoContext) {
    unsigned int slotsize = dimension * dimension;
    std::vector<std::complex<double>> resultVect = std::vector<std::complex<double>>(slotsize);
    unsigned int vectSize = vect.size();
    for (int iteration = 0; iteration < slotsize/vectSize; iteration++) {
        for (int pos = 0; pos < vectSize; pos++) {
            resultVect[pos + iteration * vectSize] = vect[pos];
        }
    }
    for (int pos = (slotsize/vectSize) * (vectSize -1); pos < slotsize; pos++) {
        resultVect[pos] = vect[pos%vectSize];
    }
    return resultVect;
}

//Fill to slotsize for a ciphertext vector
Ciphertext<DCRTPoly> getFilledVector(Ciphertext<DCRTPoly> vect, unsigned int dimension, CryptoContext<DCRTPoly> cryptoContext) {
    unsigned int slotsize = dimension * dimension;
    Ciphertext<DCRTPoly> vectCopy = vect->Clone();
    for (int rotations = 1; rotations < slotsize/dimension; rotations++) {
        vectCopy = cryptoContext->EvalRotate(vectCopy, -dimension);
        vect = cryptoContext->EvalAdd(vect, vectCopy);
    }
    int overflow = slotsize - ((slotsize/dimension) * (dimension-1));
    std::vector<std::complex<double>> mask = {};
    for (int pos = 0; pos < slotsize; pos++) {
        if (pos < overflow) {
            mask.push_back(1);
        } else {
            mask.push_back(0);
        }
    }
    Plaintext PTmask = cryptoContext->MakeCKKSPackedPlaintext(mask);
    auto temp = cryptoContext->EvalMult(vect, PTmask);
    auto vectEnd = cryptoContext->EvalRotate(temp, overflow);
    auto result = cryptoContext->EvalAdd(vect, vectEnd);
    return result;
}

//Algo for generating sigma transform matrix
std::vector<std::complex<double>> generateSigmaMatrix(int diagonalNum, unsigned int dimension) {
    unsigned int size = dimension * dimension;
    std::vector<std::complex<double>> transformMatrix = std::vector<std::complex<double>>(size);
    if (diagonalNum >= 0) {
        for (int pos = 0; pos < size; pos++) {
            int checkFormula = pos - dimension * diagonalNum;
            if (checkFormula >= 0 && checkFormula < (dimension - diagonalNum)) {
                transformMatrix[pos] = 1;
            } else {
                transformMatrix[pos] = 0;
            }
        }
    } else {
        for (int pos = 0; pos < size; pos++) {
            int checkFormula = pos - (dimension + diagonalNum) * dimension;
            if (checkFormula >= -diagonalNum && checkFormula < dimension) {
                transformMatrix[pos] = 1;
            } else {
                transformMatrix[pos] = 0;
            }
        }
    }
    return transformMatrix;
}

//dimension is the length of a row/col in the square matrix
std::vector<std::complex<double>> generateTransformMatrix(transformMatrixTypes type, int diagonalNum, unsigned int dimension) {
    unsigned int size = dimension * dimension;
    std::vector<std::complex<double>> transformMatrix = std::vector<std::complex<double>>(size);
    switch(type) {
        case sigma:
            return generateSigmaMatrix(diagonalNum, dimension);
            break;
        case tau:
            break;
        case rowShift:
            break;
        case colShift:
            break;
    }
    return {};
}

//Assume cipher matrix is in concatenated diagonal packing form, matrix cipher length = l^2, vector length = l
Ciphertext<DCRTPoly> matrixVectorProduct(Ciphertext<DCRTPoly> concatDiagPackMatrix, Plaintext vect, CryptoContext<DCRTPoly> cryptoContext, unsigned int dimension, KeyPair<DCRTPoly> keys) {
    std::vector<std::complex<double>> originalVect = vect->GetCKKSPackedValue();
    auto filledVect = getFilledVector(originalVect, dimension, cryptoContext);
    Plaintext packedVect = cryptoContext->MakeCKKSPackedPlaintext(filledVect);
    Ciphertext<DCRTPoly> sum = cryptoContext->EvalMult(concatDiagPackMatrix, packedVect);
    // Plaintext result1;
    // cryptoContext->Decrypt(keys.secretKey, concatDiagPackMatrix, &result1);
    // std::cout << "original matrix: " << result1 << std::endl;
    Ciphertext<DCRTPoly> rotatedConcatDiagPackMatrix = concatDiagPackMatrix;
    for (int rotation = 1; rotation < dimension; rotation++) {
        rotatedConcatDiagPackMatrix = cryptoContext->EvalRotate(rotatedConcatDiagPackMatrix, dimension);
        // Plaintext result;
        // cryptoContext->Decrypt(keys.secretKey, rotatedConcatDiagPackMatrix, &result);
        // std::cout << "rotated matrix: " << result << std::endl;
        std::rotate(filledVect.begin(), filledVect.begin()+1, filledVect.end());
        Plaintext rotatedPackedVector = cryptoContext->MakeCKKSPackedPlaintext(filledVect);
        // std::cout << rotatedPackedVector << std::endl;
        sum = cryptoContext->EvalAdd(sum, cryptoContext->EvalMult(rotatedConcatDiagPackMatrix, rotatedPackedVector));
    }
    return sum;
}


//ctext matrix with ctext vect
Ciphertext<DCRTPoly> matrixVectorProduct(Ciphertext<DCRTPoly> concatDiagPackMatrix, Ciphertext<DCRTPoly> vect, CryptoContext<DCRTPoly> cryptoContext, unsigned int dimension, KeyPair<DCRTPoly> keys) {
    auto filledVect = getFilledVector(vect, dimension, cryptoContext); 
    Ciphertext<DCRTPoly> sum = cryptoContext->EvalMult(concatDiagPackMatrix, filledVect);
    Ciphertext<DCRTPoly> rotatedConcatDiagPackMatrix = concatDiagPackMatrix;
    auto rotatedFilledVector = filledVect;
    // Plaintext result1;
    // cryptoContext->Decrypt(keys.secretKey, concatDiagPackMatrix, &result1);
    // std::cout << "original matrix: " << result1 << std::endl;
    for (int rotation = 1; rotation < dimension; rotation++) {
        rotatedConcatDiagPackMatrix = cryptoContext->EvalRotate(rotatedConcatDiagPackMatrix, dimension);
        // Plaintext result;
        // cryptoContext->Decrypt(keys.secretKey, rotatedConcatDiagPackMatrix, &result);
        // std::cout << "rotated matrix: " << result << std::endl;
        rotatedFilledVector = cryptoContext->EvalRotate(rotatedFilledVector, 1);
        // Plaintext result2;
        // cryptoContext->Decrypt(keys.secretKey, rotatedFilledVector, &result2);
        // std::cout << "rotated vector: " << result2 << std::endl;
        sum = cryptoContext->EvalAdd(sum, cryptoContext->EvalMult(rotatedConcatDiagPackMatrix, rotatedFilledVector));
    }
    return sum;
}

//ptext matrix with ctext vect, assume ptext matrix is in diagonal packing form already, else use rotateConcatDiagEncode() for rotation of ptext matrix instead
Ciphertext<DCRTPoly> matrixVectorProduct(Plaintext PTMatrix, Ciphertext<DCRTPoly> vect, CryptoContext<DCRTPoly> cryptoContext, unsigned int dimension, KeyPair<DCRTPoly> keys) {
    //Check if is square matrix
    if (!(ceil((double)sqrt(PTMatrix->GetLength())) == floor((double)sqrt(PTMatrix->GetLength())))) {
        throw "Not a square matrix";
    }
    auto filledVect = getFilledVector(vect, dimension, cryptoContext); 
    Ciphertext<DCRTPoly> sum = cryptoContext->EvalMult(PTMatrix, filledVect);
    // std::cout << "original matrix: " << PTMatrix << std::endl;
    cipherMatrix cMatrix = cipherMatrix(PTMatrix, cryptoContext);
    Plaintext rotatedConcatDiagPackMatrix = PTMatrix;
    for (int rotation = 1; rotation < dimension; rotation++) {
        rotatedConcatDiagPackMatrix = cMatrix.rotateEncode(rotation*dimension);
        // std::cout << "rotated matrix: " << rotatedConcatDiagPackMatrix << std::endl;
        auto rotatedFilledVector = cryptoContext->EvalRotate(filledVect, rotation);
        // Plaintext result2;
        // cryptoContext->Decrypt(keys.secretKey, rotatedFilledVector, &result2);
        // std::cout << "rotated vector: " << result2 << std::endl;
        sum = cryptoContext->EvalAdd(sum, cryptoContext->EvalMult(rotatedConcatDiagPackMatrix, rotatedFilledVector));
    }
    return sum;
}

int main() {
    //Setting cryptoContext parameters
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetPlaintextModulus(257); // p
    parameters.SetRingDim(128); // n =  m/2
    parameters.SetMultiplicativeDepth(6);
    parameters.SetScalingModSize(50);
    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

    //Setting matrix and vector values
    std::vector<std::vector<std::complex<double>>> matrix = {{1,2,3,4,4,4,4,4}, {5,6,7,8,8,8,8,8}, {9,10,11,12,12,12,12,12}, {13,14,15,16,16,16,16,16},{1,2,3,4,4,4,4,4}, {5,6,7,8,8,8,8,8}, {9,10,11,12,12,12,12,12}, {13,14,15,16,16,16,16,16}};
    std::vector<std::complex<double>> vect = {1,2,3,4,5,6,7,8};

    //creating formats for matrix and vector
    Plaintext PTvect = cc->MakeCKKSPackedPlaintext(vect);
    cipherMatrix m1 = cipherMatrix(matrix, cc);
    Plaintext PTMatrix = m1.concatDiagEncode();
    Ciphertext<DCRTPoly> CTvect = cc->Encrypt(m1.getKeys().publicKey, PTvect);
    Ciphertext<DCRTPoly> cipherM = m1.concatDiagEncodeAndEncrypt();

    //Calculate matrix vector products:

    //Cipher matrix, plaintext vector
    try {
        auto temp = matrixVectorProduct(cipherM, PTvect, cc, 8, m1.getKeys());
        Plaintext result;
        cc->Decrypt(m1.getKeys().secretKey, temp, &result);
        std::cout << "Cipher matrix multiplied with plaintext vector: " << std::endl;
        std::cout << result << std::endl;
        std::cout << "-----------------------------------------------------------------------------------" << std::endl;
    } catch (char const* err) {
        std::cout << err << std::endl;
    }

    //Cipher matrix, cipher vector
    try {
        auto temp2 = matrixVectorProduct(cipherM, CTvect, cc, 8, m1.getKeys());
        Plaintext result2;
        cc->Decrypt(m1.getKeys().secretKey, temp2, &result2);
        std::cout << "Cipher matrix multiplied with cipher vector: " << std::endl;
        std::cout << result2 << std::endl;
        std::cout << "-----------------------------------------------------------------------------------" << std::endl;
    } catch (char const* err) {
        std::cout << err << std::endl;
    }


    //Plaintext matrix, cipher vector
    try {
        auto temp3 = matrixVectorProduct(PTMatrix, CTvect, cc, 8, m1.getKeys());
        Plaintext result3;
        cc->Decrypt(m1.getKeys().secretKey, temp3, &result3);
        std::cout << "Plaintext matrix multiplied with plaintext vector: " << std::endl;
        std::cout << result3 << std::endl;
        std::cout << "-----------------------------------------------------------------------------------" << std::endl;
    } catch (char const* err) {
        std::cout << err << std::endl;
    }

    //Check results of encoding and encryption
    // m1.diagonalEncodeAndEncrypt();
    // m1.rowEncodeAndEncrypt();
    // m1.summary();
}