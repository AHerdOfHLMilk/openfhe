#include "openfhe.h"
#include <math.h>
#include <cmath>
#include <vector>
#include <ctype.h>
#include <string>

using namespace lbcrypto;

//Convert a vector to a ciphertext evaluated by a polynomial of input coeffs
Ciphertext<DCRTPoly> toPolyCC(CryptoContext<DCRTPoly> cc,  KeyPair<DCRTPoly> keys, std::vector<std::complex<double>> value, std::vector<double> coeffs) {
    //encode to plaintext
    Plaintext plain = cc->MakeCKKSPackedPlaintext(value);
    //Encrypt
    auto cipher = cc->Encrypt(keys.publicKey, plain);
    //Evaluate polynomial
    auto poly = cc->EvalPoly(cipher, coeffs);
    return poly;
}

double test(double val) {
    return val*val*val + 4*val + 12;
}

int main() {
    //set params
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(6);
    parameters.SetScalingModSize(50);

    //enable features
    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);

    //generate keys
    auto keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);
    
    //poly eval
    std::vector<std::complex<double>> vector = {0.5, 0.7, 0.9, 0.95, 0.93};
    std::vector<double> coeffs = {1,2,3,4,5};
    auto cipher = toPolyCC(cc, keys, vector, coeffs);

    //check if correct
    Plaintext result;
    cc->Decrypt(keys.secretKey, cipher, &result);
    result->SetLength(vector.size());
    std::cout << "Result is:" << std::endl;
    std::cout << result << std::endl;

    return 0;
}

