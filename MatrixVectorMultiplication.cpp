 #include "cipherTensor.h"
 #include "internalTensor.h"

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

int main() {
    //Setting cryptoContext parameters
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetPlaintextModulus(257); // p
    parameters.SetRingDim(128); // n =  m/2
    parameters.SetMultiplicativeDepth(6);
    parameters.SetScalingModSize(50);
    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    auto keypair = cc->KeyGen();
    cc->EvalMultKeyGen(keypair.secretKey);
    cc->EvalRotateKeyGen(keypair.secretKey, {-4,-3,-2,-1,0,1,2,3,4});


    //Setting matrix and vector values
    std::vector<std::vector<dbl>> matrix = {{1,2,3,4}, {5,6,7,8}, {9,10,11,12}, {13,14,15,16}};
    std::vector<std::vector<dbl>> matrix2 = {{13,14,15,16}, {5,6,7,8}, {9,10,11,12}, {13,14,15,16}};
    std::vector<dbl> vect = {1,2,3,4};

    //creating formats for matrix and vector
    auto packedVectors = getPackedVector(vect, 1);
    internalTensor ptxtVect = internalTensor::initInternalMatrixInRowForm(packedVectors);
    cipherTensor ctxtVect = cipherTensor(ptxtVect, cc, false, keypair);

    internalTensor ptxtMatrix = internalTensor::initInternalMatrixInDiagForm(matrix);
    cipherTensor ctxtMatrix = cipherTensor(ptxtMatrix, cc, true, keypair);

    //Packed matrix and packed vector verson:

    //Cipher matrix, cipher vector
    try {
        //serial
        // auto start_time = std::chrono::high_resolution_clock::now(); 
        auto temp1 = cipherTensor::encMtxVectMult(ctxtMatrix, ctxtVect, cc);
        auto resultCtxt1 = temp1.getCipher()[0];
        // auto end_time = std::chrono::high_resolution_clock::now(); 
        // std::chrono::duration<double> serial_duration = end_time - start_time;
        // std::cout << "serial duration" << serial_duration.count() << "seconds" << std::endl;

        //parallel
        // auto start_time2 = std::chrono::high_resolution_clock::now(); 
        // auto temp4 = cipherTensor::encMtxVectMult(ctxtMatrix, ctxtVect, cc);
        // auto end_time2 = std::chrono::high_resolution_clock::now(); 
        // std::chrono::duration<double> parallel_duration = end_time2 - start_time2;
        // std::cout << "parallel duration" << parallel_duration.count() << "seconds" << std::endl;

        Plaintext result1;
        cc->Decrypt(keypair.secretKey, resultCtxt1, &result1);
        std::cout << "Cipher matrix multiplied with cipher vector: " << std::endl;
        std::cout << result1 << std::endl;
        std::cout << "-----------------------------------------------------------------------------------" << std::endl;
    } catch (char const* err) {
        std::cout << err << std::endl;
    }

    try {
        auto temp2 = cipherTensor::encMtxPlainVectMult(ctxtMatrix, ptxtVect, cc);
        auto resultCtxt2 = temp2.getCipher()[0];

        Plaintext result2;
        cc->Decrypt(keypair.secretKey, resultCtxt2, &result2);
        std::cout << "Cipher matrix multiplied with cipher vector: " << std::endl;
        std::cout << result2 << std::endl;
        std::cout << "-----------------------------------------------------------------------------------" << std::endl;
    } catch (char const* err) {
        std::cout << err << std::endl;
    }

    try {
        auto temp3 = cipherTensor::plainMtxEncVectMult(ptxtMatrix, ctxtVect, cc);
        auto resultCtxt3 = temp3.getCipher()[0];

        Plaintext result3;
        cc->Decrypt(keypair.secretKey, resultCtxt3, &result3);
        std::cout << "Cipher matrix multiplied with cipher vector: " << std::endl;
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