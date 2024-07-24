#include <vector>
#include <complex>
#include <iostream>

typedef std::complex<double> dbl;
typedef vct vct;
typedef mtx mtx;


//Internal Tensor handles the matrix row/column/diagonal operations, as well as packing and form transformations of square matrice or vector
class internalTensor {
    private:
    mtx matrix;
    unsigned int rowsize;
    unsigned int colsize;
    bool isVect = (rowsize == colsize && rowsize != 0 && colsize != 0);
    bool isDiag = false;

    private:
    internalTensor() {
        this->matrix = {};
        this->rowsize = 0;
        this->colsize = 0;
    }

    //initialise zeros square matrix of specified size
    internalTensor(unsigned int length) {
        //default value is 0
        matrix.resize(length, vct(length, 0.0)); 
        this->rowsize = length;
        this->colsize = length;
    }

    //initialise square matrix from existing square matrix in split form
    internalTensor(mtx m, bool isDiag) {
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
    internalTensor(vct v) {
        this->matrix = {};
        this->matrix.push_back(v);
        this->rowsize = 1;
        this->colsize = v.size();
    }

    public:
    static internalTensor initInternalVector(vct v) {
        return internalTensor(v);
    }

    static internalTensor initInternalMatrixInRowForm(mtx m) {
        return internalTensor(m, false);
    }

    static internalTensor initInternalMatrixInDiagForm(mtx m) {
        return internalTensor(m, true);
    }

    //Getter/Setter methods
    bool isVector() {
        return this->isVect;
    }

    //Return the matrix in vector vector form
    mtx getMatrix() {
        return mtx(matrix);
    }

    unsigned int getColSize() {
        return this->colsize;
    }

    unsigned int getRowSize() {
        return this->rowsize;
    }

    vct getRow(unsigned int pos) {
        return this->matrix[pos];
    }

    dbl getElem(unsigned int row, unsigned int col) {
        return matrix[row][col];
    }

    void set(unsigned int row, unsigned int col, double val) {
        matrix[row][col] = val;
    }

    //Obtain diagonal packing format
    mtx getDiagonalVectors() {
        if (isDiag) {
            return this->matrix;
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
    vct getDiagonalConcatenationVector() {
        vct diagPackVector = {};
        if (isDiag) {
            diagPackVector.push_back(this->matrix[0]);
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
    vct getRowConcatenationVector() {
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