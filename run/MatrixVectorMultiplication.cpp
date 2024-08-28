
 #include "../source/cipherTensor.h"
 #include "../source/internalTensor.h"
 #include "../source/utilities.h"

 using namespace lbcrypto;

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

int main() {

    unsigned int dim = 4; //size of width/length of matrix (update manually for testing)

    //Setting cryptoContext parameters
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetRingDim(dim*dim*2); // n =  m/2 must set slot size to be equal to matrix size
    parameters.SetMultiplicativeDepth(20);
    parameters.SetScalingModSize(50);
    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    KeyPair<DCRTPoly> keypair = cc->KeyGen();
    cc->EvalMultKeyGen(keypair.secretKey);
    cc->EvalRotateKeyGen(keypair.secretKey, generateRotateIndexList(-dim*dim,dim*dim));


    //Setting matrix and vector values
    std::vector<std::vector<dbl>> matrix = {{1,2,3,4}, {5,6,7,8}, {9,10,11,12}, {13,14,15,16}};
    std::vector<std::vector<dbl>> matrix2 = {{13,14,15,16}, {5,6,7,8}, {9,10,11,12}, {13,14,15,16}};
    std::vector<dbl> vect = {1,2,3,4};

    //creating formats for matrix and vector
    auto packedVectors = getPackedVector(vect, 1);
    internalTensor ptxtVect = internalTensor::initInternalPackedVectors(packedVectors);
    cipherTensor ctxtVect = cipherTensor(ptxtVect, cc, false, keypair);

    internalTensor ptxtMatrix = internalTensor::initInternalMatrixForMxM(matrix);
    internalTensor ptxtMatrix2 = internalTensor::initInternalMatrixForMxM(matrix2);
    cipherTensor ctxtMatrix = cipherTensor(ptxtMatrix, cc, true, keypair);
    cipherTensor ctxtMatrix2 = cipherTensor(ptxtMatrix2, cc, true, keypair);
    //Packed matrix and packed vector verson:

    //Cipher matrix, cipher vector
    // try {
    //     //serial
    //     // auto start_time = std::chrono::high_resolution_clock::now(); 
    //     auto temp1 = cipherTensor::encMtxVectMult(ctxtMatrix, ctxtVect, cc);
    //     auto resultCtxt1 = temp1.getCipher()[0];
    //     // auto end_time = std::chrono::high_resolution_clock::now(); 
    //     // std::chrono::duration<double> serial_duration = end_time - start_time;
    //     // std::cout << "serial duration" << serial_duration.count() << "seconds" << std::endl;

    //     //parallel
    //     // auto start_time2 = std::chrono::high_resolution_clock::now(); 
    //     // auto temp4 = cipherTensor::encMtxVectMult(ctxtMatrix, ctxtVect, cc);
    //     // auto end_time2 = std::chrono::high_resolution_clock::now(); 
    //     // std::chrono::duration<double> parallel_duration = end_time2 - start_time2;
    //     // std::cout << "parallel duration" << parallel_duration.count() << "seconds" << std::endl;

    //     Plaintext result1;
    //     cc->Decrypt(keypair.secretKey, resultCtxt1, &result1);
    //     std::cout << "Cipher matrix multiplied with cipher vector: " << std::endl;
    //     std::cout << result1 << std::endl;
    //     std::cout << "-----------------------------------------------------------------------------------" << std::endl;
    // } catch (char const* err) {
    //     std::cout << err << std::endl;
    // }

    // //Cipher matrix, ptext vector
    // try {
    //     auto temp2 = cipherTensor::encMtxPlainVectMult(ctxtMatrix, ptxtVect, cc);
    //     auto resultCtxt2 = temp2.getCipher()[0];

    //     Plaintext result2;
    //     cc->Decrypt(keypair.secretKey, resultCtxt2, &result2);
    //     std::cout << "Cipher matrix multiplied with cipher vector: " << std::endl;
    //     std::cout << result2 << std::endl;
    //     std::cout << "-----------------------------------------------------------------------------------" << std::endl;
    // } catch (char const* err) {
    //     std::cout << err << std::endl;
    // }

    // //ptext matrix, cipher vector
    // try {
    //     auto temp3 = cipherTensor::plainMtxEncVectMult(ptxtMatrix, ctxtVect, cc);
    //     auto resultCtxt3 = temp3.getCipher()[0];

    //     Plaintext result3;
    //     cc->Decrypt(keypair.secretKey, resultCtxt3, &result3);
    //     std::cout << "Cipher matrix multiplied with cipher vector: " << std::endl;
    //     std::cout << result3 << std::endl;
    //     std::cout << "-----------------------------------------------------------------------------------" << std::endl;
    // } catch (char const* err) {
    //     std::cout << err << std::endl;
    // }

    try {
        
        auto temp4 = cipherTensor::matrixMult(ctxtMatrix, ctxtMatrix2, dim, cc, keypair);
        auto resultCtxt4 = temp4.getCipher()[0];

        Plaintext result4;
        cc->Decrypt(keypair.secretKey, resultCtxt4, &result4);
        std::cout << "Cipher matrix multiplied with cipher matrix: " << std::endl;
        std::cout << result4 << std::endl;
        std::cout << "-----------------------------------------------------------------------------------" << std::endl;

        std::cout << "Expected result:" << std::endl;
        vct result = mulMat(matrix, matrix2, dim);
        for (auto elem : result){
            std::cout << elem << ", ";
        } 
        std::cout << std::endl;
    } catch (char const* err) {
        std::cout << err << std::endl;
    }



    //Check results of encoding and encryption
    // m1.diagonalEncodeAndEncrypt();
    // m1.rowEncodeAndEncrypt();
    // m1.summary();
}