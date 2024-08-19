#include "internalTensor.h"


typedef std::complex<double> dbl;
typedef std::vector<dbl> vct;
typedef std::vector<std::vector<dbl>> mtx;

//initialise zeros square matrix of specified size
internalTensor::internalTensor(unsigned int length) {
    //default value is 0
    matrix.resize(length, vct(length, 0.0)); 
    this->rowsize = length;
    this->colsize = length;
}

//initialise square matrix from existing square matrix in split form
internalTensor::internalTensor(mtx m, bool isVects, bool isRowConcat) {
    this->matrix = {};
    this->rowsize = m.size();
    for (auto v : m) {
        this->colsize = v.size();
        if (this->colsize != this->rowsize) {
            this->matrix = {};
            throw "Not a square matrix";
        }
        auto temp = vct(v);
        this->matrix.push_back(temp);
    }
    if (isRowConcat) {
        mtx temp = {};
        temp.push_back(getRowConcatenationVector());
        this->matrix = temp;
        this->isE2DM = true;
    }
    if (!isVects) {
        this->matrix = getDiagonalVectors();
    }
    if (!isRowConcat && isVects) {
        this->isVect = isVects;
    }
}

//initialise vector internalTensor
internalTensor::internalTensor(vct v) {
    this->matrix = {};
    this->matrix.push_back(v);
    this->rowsize = 1;
    this->colsize = v.size();
    this->isVect = true;
}

internalTensor internalTensor::initInternalVector(vct v) {
    return internalTensor(v);
}

internalTensor internalTensor::initInternalPackedVectors(mtx v) {
    return internalTensor(v, true, false);
}

internalTensor internalTensor::initInternalMatrix(mtx m) {
    return internalTensor(m, false, false);
}

internalTensor internalTensor::initInternalMatrixForMxM(mtx m) {
    return internalTensor(m, true, true);
}

//Getter/Setter methods
bool internalTensor::isVector() {
    return this->isVect;
}

//Return the matrix in vector vector form
mtx internalTensor::getMatrix() {
    return mtx(matrix);
}

unsigned int internalTensor::getColSize() {
    return this->colsize;
}

unsigned int internalTensor::getRowSize() {
    return this->rowsize;
}

vct internalTensor::getRow(unsigned int pos) {
    return this->matrix[pos];
}

dbl internalTensor::getElem(unsigned int row, unsigned int col) {
    return matrix[row][col];
}

void internalTensor::set(unsigned int row, unsigned int col, double val) {
    matrix[row][col] = val;
}

//Obtain packed vector form for matrix vector multiplication
mtx internalTensor::getPackedVector() {
    auto vect = this->matrix[0];
    mtx packedVector = {};
    packedVector.push_back(vect);
    for (int rotation = 1; rotation < getColSize(); rotation++) {
        std::rotate(vect.begin(), vect.begin()+1, vect.end());
        packedVector.push_back(vect);
    }
    return packedVector;
}

//Obtain diagonal packing format
mtx internalTensor::getDiagonalVectors() {
    mtx diagPackVector = {};
    for (int row = 0; row < getRowSize(); row++) {
        vct temp = {};
        for (int col = 0; col < getColSize(); col++) {
            temp.push_back(getElem(col, (col + row) % getColSize()));
        }
        diagPackVector.push_back(temp);
    }
    return diagPackVector;
}

//Obtain row packing format
vct internalTensor::getRowConcatenationVector() {
    vct rowPackVector = {};
    for (int row = 0; row < getRowSize(); row++) {
        for (int col = 0; col < getColSize(); col++) {
            rowPackVector.push_back(getElem(row,col));
        }
    }
    return rowPackVector;
}

//print function
void internalTensor::printMatrix() {
    for (auto vector : matrix) {
        std::cout << "(";
        for (auto elem : vector) {
            std::cout << elem << ", ";
        }
        std::cout << ")" << std::endl;
    }
}