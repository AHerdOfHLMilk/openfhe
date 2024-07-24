//External structure for taking in the cryptocontext and encoding and encryption
//--------------------------------------------------------------------------------------------------------------------------------------------------

class cipherTensor { //can jus convert the various storing of forms into jus a flag bcos will only ever be 1 form at a time
    private:

    //data-storing variables

    //Internal Matrix, evalRotate index list and crypto keypair
    std::vector<internalTensor> matrixList = {};
    std::vector<int> rotateIndexList = {};
    KeyPair<DCRTPoly> keys;

    std::vector<Ciphertext<DCRTPoly>> diagVectorCiphers; //if vector can jus make it size 1 of the vect cipertexts

    Ciphertext<DCRTPoly> rowVectorCipher;
    
    Ciphertext<DCRTPoly> concatDiagVectorCipher;

    CryptoContext<DCRTPoly> cryptoContext;

    //flags for summary function
    bool decrypted = false;
    bool diagEncrypted = false;
    bool rowEncrypted = false;
    bool encrypted = false;
    bool isVector = false;

    private:
    //standard constructor steps to set up cryptoContext
    cipherTensor(CryptoContext<DCRTPoly> cryptoContext, KeyPair<DCRTPoly> keypair) {
        this->cryptoContext = cryptoContext;
        this->keys = keypair;
        cryptoContext->EvalMultKeyGen(keys.secretKey);
    }

    public:

    //constructing from a vector of vector matrix
    cipherTensor(std::vector<std::vector<dbl>> inputMatrix, CryptoContext<DCRTPoly> cryptoContext, KeyPair<DCRTPoly> keypair) 
    : cipherTensor(internalTensor(inputMatrix), cryptoContext, keypair){
        setRotateIndexList();
    }

    //constructing from a vector of row concatenated form of matrix
    cipherTensor(std::vector<dbl> inputMatrix, CryptoContext<DCRTPoly> cryptoContext, KeyPair<DCRTPoly> keypair) 
    : cipherTensor(internalTensor(inputMatrix, 0), cryptoContext, keypair){
        setRotateIndexList();
    }

    //constructing from a internalTensor
    cipherTensor(internalTensor inputMatrix, CryptoContext<DCRTPoly> cryptoContext, KeyPair<DCRTPoly> keypair) : cipherTensor(cryptoContext, keypair) {
        matrixList.push_back(inputMatrix);
        setRotateIndexList();
        decrypted = true;
    }

    //constructing from a ptext Matrix (must be square matrix, assume ptext matrix in concat row form)
    cipherTensor(Plaintext inputMatrix, CryptoContext<DCRTPoly> cryptoContext, KeyPair<DCRTPoly> keypair) : cipherTensor(cryptoContext, keypair) {
        auto concatRowInputMatrix = inputMatrix->GetCKKSPackedValue();
        matrixList.push_back(internalTensor(concatRowInputMatrix, 0));
        setRotateIndexList();
        decrypted = true;
    }

    //constructing from a ciphertext matrix (only for matrix vector product)
    cipherTensor(Ciphertext<DCRTPoly> inputMatrix, CryptoContext<DCRTPoly> cryptoContext, KeyPair<DCRTPoly> keypair) : cipherTensor(cryptoContext, keypair) {
        concatDiagVectorCipher = inputMatrix;
        setRotateIndexList();
        diagEncrypted = true;
    }

    cipherTensor makeVectorCipherTensor(std::vector<dbl> inputVector, CryptoContext<DCRTPoly> cryptoContext, KeyPair<DCRTPoly> keypair) {
        cipherTensor ct = cipherTensor(cryptoContext, keypair);
        ct.matrixList.push_back(internalTensor(inputVector, 1));
        ct.isVector = true;
        setRotateIndexList();
        return ct;
    }

    void setRotateIndexList() {
        for (int rotations = 1; rotations < this->matrixList[0].getMaxDimension()+1; rotations ++) {
            rotateIndexList.push_back(rotations);
            rotateIndexList.push_back(-rotations);
        }
        cryptoContext->EvalRotateKeyGen(keys.secretKey, rotateIndexList); //TODO:all key gen shld be outside the ctensor then passed in for debugging only
    }

    KeyPair<DCRTPoly> getKeys() {
        return keys;
    }

    //TODO: ciphertensor should onky contain the ciphertexts, and operations on ciphertexts, everything else should be moved 
    //Retrieve matrix
    internalTensor getMatrix(unsigned int pos) {
        return this->matrixList[pos];
    }

    void addPlainMatrix(std::vector<std::vector<dbl>> matrix) {
        this->matrixList.push_back(internalTensor(matrix));
    }

        //Retrieve matrix list in diagonal packing
    std::vector<std::vector<std::vector<dbl>>> getMatrixList() {
        std::vector<std::vector<std::vector<dbl>>> outputMatrixList = {};
        for (auto matrix : matrixList) {
            outputMatrixList.push_back(matrix.getMatrix());
        }
        return outputMatrixList;
    }

    //Retrieve matrix list in diagonal packing
    std::vector<std::vector<std::vector<dbl>>> getDiagMatrixList() {
        std::vector<std::vector<std::vector<dbl>>> outputMatrixList = {};
        for (auto matrix : matrixList) {
            outputMatrixList.push_back(matrix.getDiagonalVectors());
        }
        return outputMatrixList;
    }

    //Matrix Operations:

    //encode std::vector vector
    Plaintext encode(std::vector<dbl> vect) {
        Plaintext PTVect = cryptoContext->MakeCKKSPackedPlaintext(vect);
        return PTVect;
    }

    //encrypt a plaintext vector
    Ciphertext<DCRTPoly> encrypt(Plaintext vect) {
        Ciphertext<DCRTPoly> cipherVect = cryptoContext->Encrypt(keys.publicKey, vect);
        return cipherVect;
    }

    //encode and encrypt a single vector
    Ciphertext<DCRTPoly> encodeAndEncrypt(std::vector<dbl> vect) {
        Plaintext plaintext = cryptoContext->MakeCKKSPackedPlaintext(vect);
        return encrypt(plaintext);
    }

    std::vector<std::vector<dbl>> concatenateMatrices(std::vector<std::vector<std::vector<dbl>>> matrices) {
        std::vector<std::vector<dbl>> concatMatrix = matrices[0];
        for (int matrixPos = 1; matrixPos < matrices.size(); matrixPos++) {
            for (int vectPos = 0; vectPos < matrices[matrixPos].size(); vectPos++) {
                std::vector<dbl> concatVector(concatMatrix[vectPos]);
                concatVector.insert(concatVector.end(), matrices[matrixPos][vectPos].begin(), matrices[matrixPos][vectPos].end());
                concatMatrix[vectPos] = concatVector;
            }
        }
        return concatMatrix;
    }

    std::vector<std::vector<dbl>> getDiagonalForm() {
        std::vector<std::vector<dbl>> concatMatrix = concatenateMatrices(getDiagMatrixList());
        
        return concatMatrix;
    }

    std::vector<dbl> getDiagonalConcatForm() {
        std::vector<std::vector<dbl>> concatMatrix = concatenateMatrices(getDiagMatrixList());
        std::vector<dbl> diagConcatVector(concatMatrix[0]);
        for (int pos = 1; pos < concatMatrix.size(); pos++) {
            diagConcatVector.insert(diagConcatVector.end(), concatMatrix[pos].begin(), concatMatrix[pos].end());
        }
        return diagConcatVector;
    }

    std::vector<dbl> getRowConcatForm() {
        std::vector<std::vector<dbl>> concatMatrix = concatenateMatrices(getMatrixList());
        std::vector<dbl> rowConcatVector(concatMatrix[0]);
        for (int pos = 1; pos < concatMatrix.size(); pos++) {
            rowConcatVector.insert(rowConcatVector.end(), concatMatrix[pos].begin(), concatMatrix[pos].end());
        }
        return rowConcatVector;
    }

    //encode and encrypt the diagonal packing of the matrix
    std::vector<Ciphertext<DCRTPoly>> diagonalEncodeAndEncrypt() {
        if (diagEncrypted) {
            return diagVectorCiphers;
        }
        std::vector<std::vector<dbl>> diagVectors = getDiagonalForm();
        for (auto vector : diagVectors) {
            diagVectorCiphers.push_back(encodeAndEncrypt(vector));
        }
        diagEncrypted = true;
        return diagVectorCiphers;
    }

    //encode and encrypt the row packing of the matrix at pos in the matrix list
    Ciphertext<DCRTPoly> rowEncodeAndEncrypt() {
        if (rowEncrypted) {
            return rowVectorCipher;
        }
        auto vect = getRowConcatForm();
        auto rowVectorPlaintext = cryptoContext->MakeCKKSPackedPlaintext(vect);
        this->rowVectorCipher = encodeAndEncrypt(vect);
        rowEncrypted = true;
        return rowVectorCipher;
    }

    //encode the rotation of the row concatenation of the matrix
    Plaintext rotateEncode (int rotation) {
        auto vect = getRowConcatForm();
        std::rotate(vect.begin(), vect.begin() + rotation, vect.end());
        auto rotatedVectorPlaintext = cryptoContext->MakeCKKSPackedPlaintext(vect);
        return rotatedVectorPlaintext;
    }

    //encode and encrypt the diagonal packing of the matrix
    Plaintext concatDiagEncode(unsigned int pos) {
        auto vect = getDiagonalConcatForm();
        auto concatDiagVectorPlaintext = cryptoContext->MakeCKKSPackedPlaintext(vect);
        return concatDiagVectorPlaintext;
    }


    //encode and encrypt the diagonal packing of the matrix
    Ciphertext<DCRTPoly> concatDiagEncodeAndEncrypt(int pos) {
        if (diagEncrypted) {
            return concatDiagVectorCipher;
        }
        this->concatDiagVectorCipher = encrypt(concatDiagEncode(pos));
        diagEncrypted = true;
        return concatDiagVectorCipher;
    }

    //Prints out the decrypted diagonal and row ciphertexts, as well as the original matrix
    void summary() {
        std::string seperator = "-------------------------------------------------------------------------------------------------------------";
        std::cout << "Summary:" << std::endl << seperator << std::endl;
        if (decrypted) {
            for (int pos = 0; pos < matrixList.size(); pos++) {
                std::cout << "Matrix " << pos << ": " << std::endl;
                this->matrixList[pos].printMatrix();
            }
            
        }
        if (diagEncrypted) {
            std::cout << "Diagonal packing encrypted matrix:" << std::endl;
            Plaintext vectorResult;
            for (auto cipher : diagVectorCiphers) {
                cryptoContext->Decrypt(keys.secretKey, cipher, &vectorResult);
                std::cout << vectorResult << std::endl;
            }
        }
        if (rowEncrypted) {
            std::cout << "Row packing encrypted matrix:" << std::endl;
            Plaintext result;
            cryptoContext->Decrypt(keys.secretKey, rowVectorCipher, &result);
            std::cout << result << std::endl;
        }
    }

};

//Non-class functions:
//1. getFilledVector(): pack plaintext full with the vector
//2. generateTransformMatrix: For generating the transform matrices inn matrix-matrix multiplication
//3. concatMatrixVectorProduct: Function to do matrix-vector mulltiplicaton (where matrix is square matrix)

enum transformMatrixTypes {
    sigma,
    tau,
    rowShift,
    colShift
};

//Algo for generating sigma transform matrix
std::vector<dbl> generateSigmaMatrix(int diagonalNum, unsigned int dimension) {
    unsigned int size = dimension * dimension;
    std::vector<dbl> transformMatrix = std::vector<dbl>(size);
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

//Algo for generating sigma transform matrix
std::vector<dbl> generateTauMatrix(int diagonalNum, unsigned int dimension) {
    unsigned int size = dimension * dimension;
    std::vector<dbl> transformMatrix = std::vector<dbl>(size);
    // if (diagonalNum >= 0) {
    //     for (int pos = 0; pos < size; pos++) {
    //         int checkFormula = pos - dimension * diagonalNum;
    //         if (checkFormula >= 0 && checkFormula < (dimension - diagonalNum)) {
    //             transformMatrix[pos] = 1;
    //         } else {
    //             transformMatrix[pos] = 0;
    //         }
    //     }
    // } else {
    //     for (int pos = 0; pos < size; pos++) {
    //         int checkFormula = pos - (dimension + diagonalNum) * dimension;
    //         if (checkFormula >= -diagonalNum && checkFormula < dimension) {
    //             transformMatrix[pos] = 1;
    //         } else {
    //             transformMatrix[pos] = 0;
    //         }
    //     }
    // }
    return transformMatrix;
}

//Algo for generating sigma transform matrix
std::vector<dbl> generateRowShiftMatrix(int diagonalNum, unsigned int dimension) {
    unsigned int size = dimension * dimension;
    std::vector<dbl> transformMatrix = std::vector<dbl>(size);
    // if (diagonalNum >= 0) {
    //     for (int pos = 0; pos < size; pos++) {
    //         int checkFormula = pos - dimension * diagonalNum;
    //         if (checkFormula >= 0 && checkFormula < (dimension - diagonalNum)) {
    //             transformMatrix[pos] = 1;
    //         } else {
    //             transformMatrix[pos] = 0;
    //         }
    //     }
    // } else {
    //     for (int pos = 0; pos < size; pos++) {
    //         int checkFormula = pos - (dimension + diagonalNum) * dimension;
    //         if (checkFormula >= -diagonalNum && checkFormula < dimension) {
    //             transformMatrix[pos] = 1;
    //         } else {
    //             transformMatrix[pos] = 0;
    //         }
    //     }
    // }
    return transformMatrix;
}

//Algo for generating sigma transform matrix
std::vector<dbl> generateColShiftMatrix(int diagonalNum, unsigned int dimension) {
    unsigned int size = dimension * dimension;
    std::vector<dbl> transformMatrix = std::vector<dbl>(size);
    for (int pos = 0; pos < size; pos++) {
        if (pos%dimension >= 0 && pos%dimension < (dimension - diagonalNum)) {
            transformMatrix[pos] = 1;
        } else if (pos%dimension < dimension && pos%dimension > (dimension - diagonalNum)) {
            transformMatrix[pos] = 1;
        } else {
            transformMatrix[pos] = 0;
        }
    }
    return transformMatrix;
}

//dimension is the length of a row/col in the square matrix
std::vector<dbl> generateTransformMatrix(transformMatrixTypes type, int diagonalNum, unsigned int dimension) {
    unsigned int size = dimension * dimension;
    std::vector<dbl> transformMatrix = std::vector<dbl>(size);
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

Plaintext vectEncode(std::vector<dbl> vect, CryptoContext<DCRTPoly> cryptoContext) {
    auto PTVect = cryptoContext->MakeCKKSPackedPlaintext(vect);
    return PTVect;
}

//encode and encrypt a vector
Ciphertext<DCRTPoly> vectEncodeAndEncrypt(std::vector<dbl> vect, CryptoContext<DCRTPoly> cryptoContext, KeyPair<DCRTPoly> keys) {
    auto PTVect = cryptoContext->MakeCKKSPackedPlaintext(vect);
    auto CTVect = cryptoContext->Encrypt(keys.publicKey, PTVect);
    return CTVect;
}

//fill to slotsize for std::vector vector
std::vector<dbl> getFilledVector(std::vector<dbl> vect, unsigned int dimension, CryptoContext<DCRTPoly> cryptoContext) {
    unsigned int slotsize = dimension * dimension;
    std::vector<dbl> resultVect = std::vector<dbl>(slotsize);
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
    std::vector<dbl> mask = {};
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

std::vector<dbl> repeatVector(std::vector<dbl> vect, unsigned int num) {
    std::vector<dbl> outputVector(vect);
    for (int count = 1; count < num; count ++) {
        outputVector.insert(outputVector.end(), vect.begin(), vect.end());
    }
    return outputVector;
}

//helper function for testing, create the packed vector for packedMatrixVector product
std::vector<std::vector<dbl>> getPackedVector(std::vector<dbl> vect, unsigned int numOfMatrices) {
    std::vector<std::vector<dbl>> packedVector = {};
    packedVector.push_back(repeatVector(vect, numOfMatrices));
    for (int rotation = 1; rotation < vect.size(); rotation++) {
        std::rotate(vect.begin(), vect.begin()+1, vect.end());
        auto insertVector = repeatVector(vect, numOfMatrices);
        packedVector.push_back(insertVector);
    }
    return packedVector;
}

//Assume cipher matrix is in concatenated diagonal packing form, matrix cipher length = l^2, vector length = l
Ciphertext<DCRTPoly> concatMatrixVectorProduct(Ciphertext<DCRTPoly> concatDiagPackMatrix, Plaintext vect, CryptoContext<DCRTPoly> cryptoContext, unsigned int dimension, KeyPair<DCRTPoly> keys) {
    std::vector<dbl> originalVect = vect->GetCKKSPackedValue();
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
Ciphertext<DCRTPoly> concatMatrixVectorProduct(Ciphertext<DCRTPoly> concatDiagPackMatrix, Ciphertext<DCRTPoly> vect, CryptoContext<DCRTPoly> cryptoContext, unsigned int dimension, KeyPair<DCRTPoly> keys) {
    auto filledVect = getFilledVector(vect, dimension, cryptoContext);
    Ciphertext<DCRTPoly> sum = cryptoContext->EvalMult(concatDiagPackMatrix, filledVect);
    Ciphertext<DCRTPoly> rotatedConcatDiagPackMatrix = concatDiagPackMatrix;
    auto rotatedFilledVector = filledVect;
    Plaintext result4;
    cryptoContext->Decrypt(keys.secretKey, filledVect, &result4);
    std::cout << "original filled vector: " << result4 << std::endl;
    Plaintext result1;
    cryptoContext->Decrypt(keys.secretKey, concatDiagPackMatrix, &result1);
    std::cout << "original matrix: " << result1 << std::endl;
    for (int rotation = 1; rotation < dimension; rotation++) {
        rotatedConcatDiagPackMatrix = cryptoContext->EvalRotate(rotatedConcatDiagPackMatrix, dimension);
        Plaintext result;
        cryptoContext->Decrypt(keys.secretKey, rotatedConcatDiagPackMatrix, &result);
        std::cout << "rotated matrix: " << result << std::endl;
        rotatedFilledVector = cryptoContext->EvalRotate(rotatedFilledVector, 1);
        Plaintext result2;
        cryptoContext->Decrypt(keys.secretKey, rotatedFilledVector, &result2);
        std::cout << "rotated vector: " << result2 << std::endl;
        sum = cryptoContext->EvalAdd(sum, cryptoContext->EvalMult(rotatedConcatDiagPackMatrix, rotatedFilledVector));
    }
    return sum;
}

//ptext matrix with ctext vect, assume ptext matrix is in diagonal packing form already, else use rotateConcatDiagEncode() for rotation of ptext matrix instead
Ciphertext<DCRTPoly> concatMatrixVectorProduct(Plaintext PTMatrix, Ciphertext<DCRTPoly> vect, CryptoContext<DCRTPoly> cryptoContext, unsigned int dimension, KeyPair<DCRTPoly> keys) {
    //Check if is square matrix
    if (!(ceil((double)sqrt(PTMatrix->GetLength())) == floor((double)sqrt(PTMatrix->GetLength())))) {
        throw "Not a square matrix";
    }
    auto filledVect = getFilledVector(vect, dimension, cryptoContext); 
    Ciphertext<DCRTPoly> sum = cryptoContext->EvalMult(PTMatrix, filledVect);
    // std::cout << "original matrix: " << PTMatrix << std::endl;
    cipherTensor cMatrix = cipherTensor(PTMatrix, cryptoContext, keys);
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

//Assume cipher matrix is in concatenated diagonal packing form, matrix cipher length = l^2, vector length = l
Ciphertext<DCRTPoly> packedMatrixVectorProduct(std::vector<Ciphertext<DCRTPoly>> diagPackMatrix, std::vector<std::vector<dbl>> vect, CryptoContext<DCRTPoly> cryptoContext, KeyPair<DCRTPoly> keys) {
    unsigned int dimension = vect.size();
    // printV(diagPackMatrix, cryptoContext, keys);
    Ciphertext<DCRTPoly> sum = cryptoContext->EvalMult(diagPackMatrix[0], vectEncode(vect[0], cryptoContext));
    // Plaintext result2;
    // cryptoContext->Decrypt(keys.secretKey, diagPackMatrix[0], &result2);
    // std::cout << "diagpackmatrix: " << result2 << std::endl;
    // Plaintext result1;
    // cryptoContext->Decrypt(keys.secretKey, sum, &result1);
    // std::cout << "sum: " << result1 << std::endl;
    for (int rotation = 1; rotation < dimension; rotation++) {
        sum = cryptoContext->EvalAdd(sum, cryptoContext->EvalMult(diagPackMatrix[rotation], vectEncode(vect[rotation], cryptoContext)));
    }
    return sum;
}


//ctext matrix with ctext vect
Ciphertext<DCRTPoly> packedMatrixVectorProduct(std::vector<Ciphertext<DCRTPoly>> diagPackMatrix, std::vector<Ciphertext<DCRTPoly>> vect, CryptoContext<DCRTPoly> cryptoContext, KeyPair<DCRTPoly> keys) {
    unsigned int dimension = vect.size();
    Ciphertext<DCRTPoly> sum = cryptoContext->EvalMult(diagPackMatrix[0], vect[0]);
    // Plaintext result1;
    // cryptoContext->Decrypt(keys.secretKey, concatDiagPackMatrix, &result1);
    // std::cout << "original matrix: " << result1 << std::endl;
    for (int rotation = 1; rotation < dimension; rotation++) {
        sum = cryptoContext->EvalAdd(sum, cryptoContext->EvalMult(diagPackMatrix[rotation], vect[rotation]));
    }
    return sum;
}

//ctext matrix with ctext vect
Ciphertext<DCRTPoly> packedParallelMatrixVectorProduct(std::vector<Ciphertext<DCRTPoly>> diagPackMatrix, std::vector<Ciphertext<DCRTPoly>> vect, CryptoContext<DCRTPoly> cryptoContext, KeyPair<DCRTPoly> keys) {
    unsigned int dimension = vect.size();
    Ciphertext<DCRTPoly> sum = cryptoContext->EvalMult(diagPackMatrix[0], vect[0]);
    // Plaintext result1;
    // cryptoContext->Decrypt(keys.secretKey, concatDiagPackMatrix, &result1);
    // std::cout << "original matrix: " << result1 << std::endl;
    #pragma omp parallel for
    for (int rotation = 1; rotation < dimension; rotation++) {

        sum = cryptoContext->EvalAdd(sum, cryptoContext->EvalMult(diagPackMatrix[rotation], vect[rotation]));
    }
    return sum;
}

//ptext matrix with ctext vect, assume ptext matrix is in diagonal packing form already, else use rotateConcatDiagEncode() for rotation of ptext matrix instead
Ciphertext<DCRTPoly> packedMatrixVectorProduct(std::vector<std::vector<dbl>> PTMatrix, std::vector<Ciphertext<DCRTPoly>> vect, CryptoContext<DCRTPoly> cryptoContext, KeyPair<DCRTPoly> keys) {
    unsigned int dimension = PTMatrix.size();
    Ciphertext<DCRTPoly> sum = cryptoContext->EvalMult(vectEncode(PTMatrix[0], cryptoContext), vect[0]);
    // Plaintext result1;
    // cryptoContext->Decrypt(keys.secretKey, concatDiagPackMatrix, &result1);
    // std::cout << "original matrix: " << result1 << std::endl;
    for (int rotation = 1; rotation < dimension; rotation++) {
        sum = cryptoContext->EvalAdd(sum, cryptoContext->EvalMult(vectEncode(PTMatrix[rotation], cryptoContext), vect[rotation]));
    }
    return sum;
}