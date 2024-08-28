#include <cstdlib>
#include "../build/_deps/googletest-src/googletest/include/gtest/gtest.h"
#include "../source/cipherTensor.h"
#include "../source/utilities.h"
#include <gtest/gtest.h>

namespace my {
namespace project {
namespace {

// The fixture for testing class Foo.
class MatrixVectorMultiplicationTest : public testing::Test {
 protected:
  // You can remove any or all of the following functions if their bodies would
  // be empty.

  vct mulMat(mtx mat1, mtx mat2, unsigned int dim) {
    vct row = std::vector<dbl>(dim, 0);
    mtx rslt = std::vector<std::vector<dbl>>(dim, row);
    for (int i = 0; i < dim; i++) {
        for (int j = 0; j < dim; j++) {
            for (int k = 0; k < dim; k++) {
                rslt[i][j] += mat1[i][k] * mat2[k][j];
            }
        }
    }
    vct returnVect = std::vector<dbl>(dim*dim);
    for (int i = 0; i < dim; i++) {
        for (int j = 0; j < dim; j++) {
            returnVect[i * dim + j] = rslt[i][j];
        }
    }
    return returnVect;
}

  MatrixVectorMultiplicationTest() {

    std::vector<int> sizes = {2, 4, 8, 16, 32};
    dim = sizes[std::rand()%5];
    int size = dim*dim;

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetRingDim(size*2); // n =  m/2 must set slot size to be equal to matrix size
    parameters.SetMultiplicativeDepth(20);
    parameters.SetScalingModSize(50);
    cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    keypair = cc->KeyGen();
    cc->EvalMultKeyGen(keypair.secretKey);
    cc->EvalRotateKeyGen(keypair.secretKey, generateRotateIndexList(-size, size));


    //Setting matrix and vector values
    // std::vector<std::vector<dbl>> matrix = {{1,2,3,4}, {5,6,7,8}, {9,10,11,12}, {13,14,15,16}};
    // std::vector<std::vector<dbl>> matrix2 = {{13,14,15,16}, {5,6,7,8}, {9,10,11,12}, {13,14,15,16}};
    for (int i = 0; i < dim; i++) {
        vct temp = {};
        vct temp2 = {};
        for (int j = 0; j < dim; j++) {
            temp.push_back(std::rand()%100);
            temp2.push_back(std::rand()%100);
        }
        matrix.push_back(temp);
        matrix.push_back(temp2);
    }
    vct vect = {};
    for (int i = 0; i < dim; i++) {
        vect.push_back(std::rand()%100);
    }

    //creating formats for matrix and vector
    auto packedVectors = getPackedVector(vect, 1);
    ptxtVect = internalTensor::initInternalPackedVectors(packedVectors);
    ctxtVect = cipherTensor(ptxtVect, cc, false, keypair);

    ptxtMatrix = internalTensor::initInternalMatrixForMxM(matrix);
    ptxtMatrix2 = internalTensor::initInternalMatrixForMxM(matrix2);
    ctxtMatrix = cipherTensor(ptxtMatrix, cc, true, keypair);
    ctxtMatrix2 = cipherTensor(ptxtMatrix2, cc, true, keypair);
  }

//   ~MatrixVectorMultiplicationTest() override {
//     ;
//   }

    mtx matrix = {};
    mtx matrix2 = {};

    internalTensor ptxtVect;
    cipherTensor ctxtVect;

    internalTensor ptxtMatrix;
    internalTensor ptxtMatrix2;
    cipherTensor ctxtMatrix;
    cipherTensor ctxtMatrix2;
    int dim;
    CryptoContext<DCRTPoly> cc;
    KeyPair<DCRTPoly> keypair;
};

// Tests that the Foo::Bar() method does Abc.
TEST_F(MatrixVectorMultiplicationTest, Random_Matrices_test) {
  
  EXPECT_EQ(cipherTensor::matrixMult(ctxtMatrix, ctxtMatrix2, dim, cc, keypair), mulMat(matrix, matrix2, dim));
}

// Tests that Foo does Xyz.
TEST_F(FooTest, DoesXyz) {
  // Exercises the Xyz feature of Foo.
}

}  // namespace
}  // namespace project
}  // namespace my

int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}