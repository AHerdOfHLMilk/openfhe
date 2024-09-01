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

  std::vector<double> mulMat(std::vector<std::vector<double>> mat1, std::vector<std::vector<double>> mat2, unsigned int dim) {
    std::vector<double> row = std::vector<double>(dim, 0);
    std::vector<std::vector<double>> rslt = std::vector<std::vector<double>>(dim, row);
    for (int i = 0; i < dim; i++) {
        for (int j = 0; j < dim; j++) {
            for (int k = 0; k < dim; k++) {
                rslt[i][j] += mat1[i][k] * mat2[k][j];
            }
        }
    }
    std::vector<double> returnVect = std::vector<double>(dim*dim);
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
    cc1 = GenCryptoContext(parameters);
    cc1->Enable(PKE);
    cc1->Enable(KEYSWITCH);
    cc1->Enable(LEVELEDSHE);
    cc1->Enable(ADVANCEDSHE);
    keypairs = cc1->KeyGen();
    cc1->EvalMultKeyGen(keypairs.secretKey);
    cc1->EvalRotateKeyGen(keypairs.secretKey, generateRotateIndexList(-size, size));


    //Setting matrix and vector values
    // std::vector<std::vector<dbl>> matrix = {{1,2,3,4}, {5,6,7,8}, {9,10,11,12}, {13,14,15,16}};
    // std::vector<std::vector<dbl>> matrix2 = {{13,14,15,16}, {5,6,7,8}, {9,10,11,12}, {13,14,15,16}};
    for (int i = 0; i < dim; i++) {
        vct temp = {};
        vct temp2 = {};
        std::vector<double> temp3 = {};
        std::vector<double> temp4 = {};
        for (int j = 0; j < dim; j++) {
          auto randomVal1 = std::rand()%100;
          auto randomVal2 = std::rand()%100;
          temp.push_back(randomVal1);
          temp2.push_back(randomVal2);
          temp3.push_back(randomVal1);
          temp4.push_back(randomVal2);
        }
        matrix.push_back(temp);
        matrix2.push_back(temp2);
        mat.push_back(temp3);
        mat2.push_back(temp4);
    }
    vct vect = {};
    for (int i = 0; i < dim; i++) {
        vect.push_back(std::rand()%100);
    }

    //creating formats for matrix and vector
    auto packedVectors = getPackedVector(vect, 1);
    ptxtVect = internalTensor::initInternalPackedVectors(packedVectors);
    ctxtVect = cipherTensor(ptxtVect, cc1, false, keypairs);

    ptxtMatrix = internalTensor::initInternalMatrixForMxM(matrix);
    ptxtMatrix2 = internalTensor::initInternalMatrixForMxM(matrix2);
    ctxtMatrix = cipherTensor(ptxtMatrix, cc1, true, keypairs);
    ctxtMatrix2 = cipherTensor(ptxtMatrix2, cc1, true, keypairs);
  }

//   ~MatrixVectorMultiplicationTest() override {
//     ;
//   }

    mtx matrix = {};
    mtx matrix2 = {};
    std::vector<std::vector<double>> mat = {};
    std::vector<std::vector<double>> mat2 = {};

    internalTensor ptxtVect;
    cipherTensor ctxtVect;

    internalTensor ptxtMatrix;
    internalTensor ptxtMatrix2;
    cipherTensor ctxtMatrix;
    cipherTensor ctxtMatrix2;
    int dim;
    CryptoContext<DCRTPoly> cc1;
    KeyPair<DCRTPoly> keypairs;
};

// Tests that the Foo::Bar() method does Abc.
TEST_F(MatrixVectorMultiplicationTest, Random_Matrices_test) {
  auto result = cipherTensor::matrixMult(ctxtMatrix, ctxtMatrix2, dim, cc1, keypairs).getCipher()[0];
  Plaintext PTResult;
  cc1->Decrypt(keypairs.secretKey, result, &PTResult);
  std::vector<double> vectResult = PTResult->GetRealPackedValue();
  auto expected = mulMat(mat, mat2, dim);
  for (int i = 0; i < expected.size(); i ++) {
    ASSERT_NEAR(vectResult[i], expected[i], 0.0001); // 4 decimal places
  }
}

int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}