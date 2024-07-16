#include <vector>
#include<algorithm>
#include "openfhe.h"
#include <string>

using namespace lbcrypto;

//Function to print out contents of a vector
void printV(std::vector<std::complex<double>> v) {
    for (auto i : v) {
        std::cout << i << ",";
    }
    std::cout << std::endl;
}

void printV(std::vector<int> v) {
    for (auto i : v) {
        std::cout << i << ",";
    }
    std::cout << std::endl;
}

//Internal matrix to abstract basic matrix functions into a matrix class
//---------------------------------------------------------------------------------------------------------------------------------------------------------
class internalMatrix {
    private:
    std::vector<std::vector<std::complex<double>>> matrix;
    unsigned int rowSize;
    unsigned int colSize;

    public:
    internalMatrix() {
        this->matrix = {};
        this->rowSize = 0;
        this->colSize = 0;
    }

    //initialise zeros matrix of specified size
    internalMatrix(unsigned int row, unsigned int col) {
        //default value is 0
        matrix.resize(row, std::vector<std::complex<double>>(col, 0.0)); 
        this->rowSize = row;
        this->colSize = col;
    }

    //initialise square matrix from existing square matrix (wo slotsize padding)
    internalMatrix(std::vector<std::vector<std::complex<double>>> m) {
        this->matrix = {};
        this->rowSize = m.size();
        this->colSize = m[0].size();
        for (auto v : m) {
            auto temp = std::vector<std::complex<double>>(v);
            matrix.push_back(temp);
        }
    }

    //initialise square matrix from existing square matrix (input in row concatenated form)
    internalMatrix(std::vector<std::complex<double>> m) {
        if (!(ceil((double)sqrt(m.size())) == floor((double)sqrt(m.size())))) {
            throw "Not a square matrix";
        }
        this->matrix = {};
        this->rowSize = std::sqrt(m.size());
        this->colSize = this->rowSize;
        unsigned int count = 0; 
        for (int rowPos = 0; rowPos < this->rowSize; rowPos++) {
            std::vector<std::complex<double>> row = {};
            for (int colPos = 0; colPos < this->colSize; colPos++) {
                row.push_back(m[count]);
                count++;
            }
            matrix.push_back(row);
        }
    }


    //initialise square matrix from existing square matrix (with slotsize padding) *WIP
    internalMatrix(std::vector<std::vector<std::complex<double>>> m, unsigned int ringDim) {
        this->matrix = {};
        this->rowSize = ringDim/2; //ring dimension / 2 = slotsize
        this->colSize = ringDim/2;
        for (auto v : m) {
            auto temp = std::vector<std::complex<double>>(v);
            temp.resize(rowSize, 0.0); //auto pad any row of matrix without enough elements with 0s
            matrix.push_back(temp);
        }
        matrix.resize(colSize, std::vector<std::complex<double>>(rowSize, 0.0));
    }

    //Getter/Setter methods
    std::vector<std::vector<std::complex<double>>> getMatrix() {
        return std::vector<std::vector<std::complex<double>>>(matrix);
    }

    unsigned int getMaxDimension() {
        if (getColSize() > getRowSize()) {
            return getColSize();
        } else {
            return getRowSize();
        }
    }

    unsigned int getColSize() {
        return this->colSize;
    }

    unsigned int getRowSize() {
        return this->rowSize;
    }

    std::vector<std::complex<double>> getRow(unsigned int pos) {
        return this->matrix[pos];
    }

    std::complex<double> getElem(unsigned int row, unsigned int col) {
        return matrix[row][col];
    }

    void set(unsigned int row, unsigned int col, double val) {
        matrix[row][col] = val;
    }

    //Obtain diagonal packing format
    std::vector<std::vector<std::complex<double>>> getDiagonalVectors() {
        std::vector<std::vector<std::complex<double>>> diagPackVector = {};
        for (int row = 0; row < getRowSize(); row++) {
            std::vector<std::complex<double>> temp = {};
            for (int col = 0; col < getColSize(); col++) {
                temp.push_back(getElem(col, (col + row) % getColSize()));
            }
            diagPackVector.push_back(temp);
        }
        return diagPackVector;
    }

    //Obtain diagonal concatenation packing format
    std::vector<std::complex<double>> getDiagonalConcatenationVector() {
        std::vector<std::complex<double>> diagPackVector = {};
        for (int row = 0; row < getRowSize(); row++) {
            for (int col = 0; col < getColSize(); col++) {
                diagPackVector.push_back(getElem(col, (col + row) % getColSize()));
            }
        }
        return diagPackVector;
    }

    //Obtain row packing format
    std::vector<std::complex<double>> getRowConcatenationVector() {
        std::vector<std::complex<double>> rowPackVector = {};
        for (int row = 0; row < getRowSize(); row++) {
            for (int col = 0; col < getColSize(); col++) {
                rowPackVector.push_back(getElem(row,col));
            }
        }
        return rowPackVector;
    }

    //print function
    void printMatrix() {
        for (auto vector : matrix) {
            std::cout << "(";
            for (auto elem : vector) {
                std::cout << elem << ", ";
            }
            std::cout << ")" << std::endl;
        }
    }
};

//External structure for taking in the cryptocontext and encoding and encryption
//--------------------------------------------------------------------------------------------------------------------------------------------------

class cipherMatrix {
    private:

    //data-storing variables

    //Internal Matrix, evalRotate index list and crypto keypair
    internalMatrix matrix;
    std::vector<int> rotateIndexList = {};
    KeyPair<DCRTPoly> keys;

    std::vector<Plaintext> diagVectorPlaintexts;
    std::vector<Ciphertext<DCRTPoly>> diagVectorCiphers;

    Plaintext rowVectorPlaintext;
    Ciphertext<DCRTPoly> rowVectorCipher;
    
    Plaintext concatDiagVectorPlaintext;
    Ciphertext<DCRTPoly> concatDiagVectorCipher;

    CryptoContext<DCRTPoly> cryptoContext;

    //flags for summary function
    bool decrypted = false;
    bool diagEncrypted = false;
    bool rowEncrypted = false;
    bool encrypted = false;

    private:
    //standard constructor steps to set up cryptoContext
    cipherMatrix(CryptoContext<DCRTPoly> cryptoContext) {
        this->cryptoContext = cryptoContext;
        cryptoContext->Enable(PKE);
        cryptoContext->Enable(KEYSWITCH);
        cryptoContext->Enable(LEVELEDSHE);
        cryptoContext->Enable(ADVANCEDSHE);
        auto keypair = cryptoContext->KeyGen();
        this->keys = keypair;
        cryptoContext->EvalMultKeyGen(keys.secretKey);
    }

    public:
    //constructing from a vector of vector matrix
    cipherMatrix(std::vector<std::vector<std::complex<double>>> inputMatrix, CryptoContext<DCRTPoly> cryptoContext) 
    : cipherMatrix(internalMatrix(inputMatrix), cryptoContext){
        setRotateIndexList();
    }

    //constructing from a vector of row concatenated form of matrix
    cipherMatrix(std::vector<std::complex<double>> inputMatrix, CryptoContext<DCRTPoly> cryptoContext) 
    : cipherMatrix(internalMatrix(inputMatrix), cryptoContext){
        setRotateIndexList();
    }

    //constructing from a internalMatrix
    cipherMatrix(internalMatrix inputMatrix, CryptoContext<DCRTPoly> cryptoContext) : cipherMatrix(cryptoContext) {
        matrix = inputMatrix;
        setRotateIndexList();
        decrypted = true;
    }

    //constructing from a ptext Matrix (must be square matrix, assume ptext matrix in concat row form)
    cipherMatrix(Plaintext inputMatrix, CryptoContext<DCRTPoly> cryptoContext) : cipherMatrix(cryptoContext) {
        auto concatRowInputMatrix = inputMatrix->GetCKKSPackedValue();
        matrix = internalMatrix(concatRowInputMatrix);
        setRotateIndexList();
        decrypted = true;
    }

    //constructing from a ciphertext matrix (only for matrix vector product)
    cipherMatrix(Ciphertext<DCRTPoly> inputMatrix, CryptoContext<DCRTPoly> cryptoContext) : cipherMatrix(cryptoContext) {
        concatDiagVectorCipher = inputMatrix;
        setRotateIndexList();
        diagEncrypted = true;
    }

    void setRotateIndexList() {
        for (int rotations = 1; rotations < this->matrix.getMaxDimension()+1; rotations ++) {
            rotateIndexList.push_back(rotations);
            rotateIndexList.push_back(-rotations);
        }
        cryptoContext->EvalRotateKeyGen(keys.secretKey, rotateIndexList);
    }

    KeyPair<DCRTPoly> getKeys() {
        return keys;
    }

    //Retrieve matrix
    internalMatrix getMatrix() {
        return this->matrix;
    }

    //Matrix Operations:

    //encode and encrypt a plaintext vector
    Ciphertext<DCRTPoly> encodeAndEncrypt(Plaintext vect) {
        Ciphertext<DCRTPoly> cipherVect = cryptoContext->Encrypt(keys.publicKey, vect);
        return cipherVect;
    }

    //encode and encrypt a single vector
    Ciphertext<DCRTPoly> encodeAndEncrypt(std::vector<std::complex<double>> vect) {
        Plaintext plaintext = cryptoContext->MakeCKKSPackedPlaintext(vect);
        return encodeAndEncrypt(plaintext);
    }

    //encode and encrypt the diagonal packing of the matrix
    std::vector<Ciphertext<DCRTPoly>> diagonalEncodeAndEncrypt() {
        if (diagEncrypted) {
            return diagVectorCiphers;
        }
        std::vector<std::vector<std::complex<double>>> diagVectors = matrix.getDiagonalVectors();
        for (auto vector : diagVectors) {
            diagVectorCiphers.push_back(encodeAndEncrypt(vector));
        }
        diagEncrypted = true;
        return diagVectorCiphers;
    }

    //encode and encrypt the row packing of the matrix
    Ciphertext<DCRTPoly> rowEncodeAndEncrypt() {
        if (rowEncrypted) {
            return rowVectorCipher;
        }
        auto vect = matrix.getRowConcatenationVector();
        this->rowVectorPlaintext = cryptoContext->MakeCKKSPackedPlaintext(vect);
        this->rowVectorCipher = encodeAndEncrypt(vect);
        rowEncrypted = true;
        return rowVectorCipher;
    }

    //encode the rotation of the row concatenation of the matrix
    Plaintext rotateEncode (int rotation) {
        auto vect = matrix.getRowConcatenationVector();
        std::rotate(vect.begin(), vect.begin() + rotation, vect.end());
        auto rotatedVectorPlaintext = cryptoContext->MakeCKKSPackedPlaintext(vect);
        return rotatedVectorPlaintext;
    }

    //encode and encrypt the diagonal packing of the matrix
    Plaintext concatDiagEncode() {
        auto vect = matrix.getDiagonalConcatenationVector();
        this->concatDiagVectorPlaintext = cryptoContext->MakeCKKSPackedPlaintext(vect);
        return concatDiagVectorPlaintext;
    }

    //rotate the diagonal packing of the matrix, then encode and encrypt
    Plaintext rotateConcatDiagEncode(int rotation) {
        auto vect = matrix.getDiagonalConcatenationVector();
        std::rotate(vect.begin(), vect.begin() + rotation, vect.end());
        auto rotatedDiagVectorPlaintext = cryptoContext->MakeCKKSPackedPlaintext(vect);
        return rotatedDiagVectorPlaintext;
    }

    //encode and encrypt the diagonal packing of the matrix
    Ciphertext<DCRTPoly> concatDiagEncodeAndEncrypt() {
        if (diagEncrypted) {
            return concatDiagVectorCipher;
        }
        this->concatDiagVectorCipher = encodeAndEncrypt(concatDiagEncode());
        diagEncrypted = true;
        return concatDiagVectorCipher;
    }

    //Prints out the decrypted diagonal and row ciphertexts, as well as the original matrix
    void summary() {
        std::string seperator = "-------------------------------------------------------------------------------------------------------------";
        std::cout << "Summary:" << std::endl << seperator << std::endl;
        if (decrypted) {
            std::cout << "Matrix: " << std::endl;
            this->matrix.printMatrix();
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

    

