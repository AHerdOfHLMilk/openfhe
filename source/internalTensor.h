#ifndef INTERNALTENSOR   // To make sure you don't declare the function more than once by including the header multiple times.
#define INTERNALTENSOR

#include <vector>
#include <complex>
#include <iostream>
#include <algorithm>

typedef std::complex<double> dbl;
typedef std::vector<dbl> vct;
typedef std::vector<std::vector<dbl>> mtx;

//TODO: add a get type (diag or not, or vector)

class internalTensor {
    public:
    mtx matrix;
    vct rowConcat;
    unsigned int rowsize;
    unsigned int colsize;

    bool isVect = false;

    internalTensor();

    //initialise zeros square matrix of specified size
    internalTensor(unsigned int length);

    //initialise square matrix from existing square matrix in split form
    internalTensor(mtx m, bool isDiag);

    //initialise vector internalTensor
    internalTensor(vct v);

    static internalTensor initInternalVector(vct v);

    static internalTensor initInternalPackedVectors(mtx m); 

    static internalTensor initInternalMatrix(mtx m);

    //Getter/Setter methods
    bool isVector();

    //Return the matrix in vector vector form
    mtx getMatrix();

    unsigned int getColSize();

    unsigned int getRowSize();

    vct getRow(unsigned int pos);

    dbl getElem(unsigned int row, unsigned int col);

    void set(unsigned int row, unsigned int col, double val);

    //Obtain packed vector form for matrix vector multiplication
    mtx getPackedVector();

    //Obtain diagonal packing format
    mtx getDiagonalVectors();

    //Obtain diagonal concatenation packing format
    vct getDiagonalConcatenationVector();

    //Obtain row packing format
    vct getRowConcatenationVector();

    //print function
    void printMatrix();
};

#endif