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
internalTensor::internalTensor(mtx m, bool isDiag) {
    this->matrix = {};
    this->rowsize = m.size();
    for (auto v : m) {
        this->colsize = v.size();
        if (this->colsize != this->rowsize) {
            this->matrix = {};
            throw "Not a square matrix";
        }
        auto temp = vct(v);
        matrix.push_back(temp);
    }
    if (isDiag) {
        this->matrix = getDiagonalVectors();
        this->isDiag = true;
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

internalTensor internalTensor::initInternalMatrixInRowForm(mtx m) {
    return internalTensor(m, false);
}

internalTensor internalTensor::initInternalMatrixInDiagForm(mtx m) {
    return internalTensor(m, true);
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
    if (isDiag) {
        return getMatrix();
    }
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

//Obtain diagonal concatenation packing format
vct internalTensor::getDiagonalConcatenationVector() {
    vct diagPackVector = {};
    if (isDiag) {
        diagPackVector = this->matrix[0];
        for (int row = 1; row < this->matrix.size(); row++) {
            diagPackVector.insert(diagPackVector.end(), this->matrix[row].begin(), this->matrix[row].end());
        }
    } else {
        for (int row = 0; row < getRowSize(); row++) {
            for (int col = 0; col < getColSize(); col++) {
                diagPackVector.push_back(getElem(col, (col + row) % getColSize()));
            }
        }
    }
    return diagPackVector;
}

//Obtain row packing format
vct internalTensor::getRowConcatenationVector() {
    if (isDiag) {
        throw "InternalTensor is in diagonal form, row form not available";
    }
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

int main() {
    // internalTensor h = internalTensor::initInternalMatrixInDiagForm({{1,2,3,4}, {5,6,7,8}, {9,10,11,12}, {13,14,15,16}});
    // std::cout<< h.getColSize() << std::endl;
    return -1;
}