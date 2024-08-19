#include "cipherTensor.h"
#include "internalTensor.h"
#include "utilities.h"


 using namespace lbcrypto;

 

std::vector<vct> concatenateMatrices(std::vector<std::vector<vct>> matrices) {
    std::vector<vct> concatMatrix = matrices[0];
    for (int matrixPos = 1; matrixPos < matrices.size(); matrixPos++) {
        for (int vectPos = 0; vectPos < matrices[matrixPos].size(); vectPos++) {
            vct concatVector(concatMatrix[vectPos]);
            concatVector.insert(concatVector.end(), matrices[matrixPos][vectPos].begin(), matrices[matrixPos][vectPos].end());
            concatMatrix[vectPos] = concatVector;
        }
    }
    return concatMatrix;
}

//encode and encrypt a vector
ctxt vectEncodeAndEncrypt(vct vect, CryptoContext<DCRTPoly> cryptoContext, KeyPair<DCRTPoly> keys) {
    auto PTVect = cryptoContext->MakeCKKSPackedPlaintext(vect);
    auto CTVect = cryptoContext->Encrypt(keys.publicKey, PTVect);
    return CTVect;
}

// //fill to slotsize for std::vector vector
// vct getFilledVector(vct vect, unsigned int dimension, CryptoContext<DCRTPoly> cryptoContext) {
//     unsigned int slotsize = dimension * dimension;
//     vct resultVect = vct(slotsize);
//     unsigned int vectSize = vect.size();
//     for (int iteration = 0; iteration < slotsize/vectSize; iteration++) {
//         for (int pos = 0; pos < vectSize; pos++) {
//             resultVect[pos + iteration * vectSize] = vect[pos];
//         }
//     }
//     for (int pos = (slotsize/vectSize) * (vectSize -1); pos < slotsize; pos++) {
//         resultVect[pos] = vect[pos%vectSize];
//     }
//     return resultVect;
// }

// //Fill to slotsize for a ciphertext vector
// ctxt getFilledVector(ctxt vect, unsigned int dimension, CryptoContext<DCRTPoly> cryptoContext) {
//     unsigned int slotsize = dimension * dimension;
//     ctxt vectCopy = vect->Clone();
//     for (int rotations = 1; rotations < slotsize/dimension; rotations++) {
//         vectCopy = cryptoContext->EvalRotate(vectCopy, -dimension);
//         vect = cryptoContext->EvalAdd(vect, vectCopy);
//     }
//     int overflow = slotsize - ((slotsize/dimension) * (dimension-1));
//     vct mask = {};
//     for (int pos = 0; pos < slotsize; pos++) {
//         if (pos < overflow) {
//             mask.push_back(1);
//         } else {
//             mask.push_back(0);
//         }
//     }
//     Plaintext PTmask = cryptoContext->MakeCKKSPackedPlaintext(mask);
//     auto temp = cryptoContext->EvalMult(vect, PTmask);
//     auto vectEnd = cryptoContext->EvalRotate(temp, overflow);
//     auto result = cryptoContext->EvalAdd(vect, vectEnd);
//     return result;
// }

vct repeatVector(vct vect, unsigned int num) {
    vct outputVector(vect);
    for (int count = 1; count < num; count ++) {
        outputVector.insert(outputVector.end(), vect.begin(), vect.end());
    }
    return outputVector;
}

//helper function for testing, create the packed vector for packedMatrixVector product
std::vector<vct> getPackedVector(vct vect, unsigned int numOfMatrices) {
    std::vector<vct> packedVector = {};
    packedVector.push_back(repeatVector(vect, numOfMatrices));
    for (int rotation = 1; rotation < vect.size(); rotation++) {
        std::rotate(vect.begin(), vect.begin()+1, vect.end());
        auto insertVector = repeatVector(vect, numOfMatrices);
        packedVector.push_back(insertVector);
    }
    return packedVector;
}

std::vector<int> geneerateRotateIndexList(int low, int high) {
    std::vector<int> indexList = {};
    for (int index = low; index <= high; index++) {
        indexList.insert(indexList.end(), index);
    }
    return indexList;
}