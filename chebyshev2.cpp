#include<algorithm>
#include<vector>
#include<cmath>
#include <iostream>
#include "openfhe.h"
#include <cstdlib>
#include <math.h>
#include <ctype.h>
#include <string>
#include "openfhe.h"
#include "chebyshev.h"

using namespace lbcrypto;

//---------------------------------------------------------------------------------------------------------------------------------------------
//Chebyshev approxmation algorithm:

constexpr double PI = 3.14159265358979323846;

//functions to test approximation
double test(double val) {
    return val*val*val + 3*val + 5;
}

double ReLU(double val) {
    return std::max((double) 0, val);
}

double leakyReLU(double val) {
    return std::max((double) 0.01*val, val);
}

//Function to print out contents of a vector
void printV(std::vector<double> v) {
    for (auto i : v) {
        std::cout << i << ",";
    }
    std::cout << std::endl;
}

//vector - vector
std::vector<double> vSubtractV(std::vector<double> v1, std::vector<double> v2) {
    std::vector<double> result(v1);
    size_t size;
    if (v1.size() > v2.size()) {
        size = v2.size();
    } else {
        size = v1.size();
    }
    for (int i = 0; i < size; i++) {
        result[i] -= v2[i];
    }
    return result;
}

//Add scaler to a vector
std::vector<double> vAdd(std::vector<double> v, double additive) {
    std::vector<double> result(v);
    for (int i = 0; i < v.size(); i++) {
        result[i] += additive;
    }
    return result;
}

//Add vector to another vector element wise
std::vector<double> vAddV(std::vector<double> v1, std::vector<double> v2) {
    std::vector<double> result(v1);
    size_t size;
    if (v1.size() > v2.size()) {
        size = v2.size();
    } else {
        size = v1.size();
    }
    for (int i = 0; i < size; i++) {
        result[i] += v2[i];
    }
    return result;
}

//vector * scalar
std::vector<double> vMultiply(std::vector<double> v, double multiplier) {
    std::vector<double> result(v);
    for (int i = 0; i < v.size(); i++) {
        result[i] *= multiplier;
    }
    return result;
}

//vector * vector
std::vector<double> vMultiplyV(std::vector<double> v1, std::vector<double> v2) {
    std::vector<double> result(v1);
    size_t size;
    if (v1.size() > v2.size()) {
        size = v2.size();
    } else {
        size = v1.size();
    }
    for (int i = 0; i < size; i++) {
        result[i] *= v2[i];
    }
    return result;
}

//apply func to vector
std::vector<double> vApply(std::vector<double> v, double (*func)(double)) {
    std::vector<double> result(v);
    for (int i = 0; i < v.size(); i++) {
        result[i] = func(v[i]);
    }
    return result;
}

//Apply a function to all elements in a vector
std::vector<double> vApply(std::vector<double> v, std::vector<double> term, double (*func)(std::vector<double>, double)) {
    std::vector<double> result(v);
    for (int i = 0; i < v.size(); i++) {
        result[i] = func(term, v[i]);
    }
    return result;
}

//Sum of values in vector
double vSum(std::vector<double> v) {
    double sum = 0;
    for (auto i : v) {
        sum += i;
    }
    return sum;
}

//Average of values in vector
double vAvrg(std::vector<double> v) {
    return vSum(v)/(double)v.size();
}
 

//vector * x**degree (shift coefficients up)
std::vector<double> vDegreeInc(std::vector<double> v, int degree) {
    std::vector<double> result(v);
    for (int i = 0; i < degree; i++) {
        result.insert(result.begin(), 0);
    }
    return result;
}

//Chebyshev polynomial recurrence function
std::vector<double> chebyRec(int term, int interval) {
    if (term == 0) {
        std::vector<double> poly = {1};
        return poly;
    }
    if (term == 1) {
        std::vector<double> poly = {0,(double) 1/interval};
        return poly;
    }
    //Recurrence relation: T(n+1) = 2x/a T(n) - T(n-1)
    std::vector<double> poly = vSubtractV(vMultiply(vDegreeInc(chebyRec(term-1, interval), 1), 2/interval), chebyRec(term-2, interval));
    return poly;
}

//Calculation of roots of chebyshev polynomials
std::vector<double> calcRoots(int degree) {
    std::vector<double> result;
    for (int i = 1; i < degree+1; i++) {
        double temp = ((2.0*i - 1.0) * PI)/(2.0*degree);
        result.push_back(-std::cos(temp));
    }
    return result;
}

//Evaluate the value of a polynomial for the given value
double polyEval(std::vector<double> term, double x) {
    double result = 0.0;
    for (int i = 0; i < term.size(); i++) {
        result += term[i] * pow(x, i);
    }
    return result;
}

//Multiply 2 polynomials
std::vector<double> polyMultiply(std::vector<double> p1, std::vector<double> p2) {
    std::vector<double> result(p1.size()*p2.size(), 0.0);
    for (int i = 0; i < p1.size(); i++) {
        for (int j = 0; j < p2.size(); j++) {
            result[i+j] = result[i+j] + (p1[i] * p2[j]);
        }
    }
    return result;
}

//Expand a polynomial to the power of n
std::vector<double> polyExpand(std::vector<double> p, int expansions) {
    std::vector<double> result;
    if (expansions == 0) {
        result = {1};
        return result;
    }
    result = p;
    for (int i = 0; i < expansions-1; i++) {
        result = polyMultiply(result, p);
    }
    return result;
}

//intermediate calculation for approximating function's coefficients calculation
std::vector<double> calcTerm(std::vector<double> term, std::vector<double> roots) {
    std::vector<double> result(roots);
    for (int i = 0; i < roots.size(); i++) {
        result[i] = polyEval(term, roots[i]);
    }
    return result;
}

//Evaluate the coefficients of the approximating polynomial
double coeffEval(std::vector<double> ys, std::vector<double> term, std::vector<double> roots, int degree) {
    auto temp = calcTerm(term, roots);
    auto temp2 = vMultiplyV(temp, ys);
    double result = 2 * vSum(temp2)/degree;
    if (std::abs(result) < pow(10, -14)) {
        return 0;
    }
    return result;
}

//Convert the aquired polynomial in u to a polynomial in x where u is the normalised version of x
std::vector<double> truncate(std::vector<double> coeffs, std::vector<std::vector<double>> chebyPolys, double intervalS, double intervalE) {
    std::vector<double> result(coeffs.size(), 0.0);
    std::vector<std::vector<double>> convPolys;
    std::vector<std::vector<double>> uConv(chebyPolys.size());
    std::vector<double> x = {(-intervalS-intervalE)/(intervalE-intervalS), 2.0/(intervalE-intervalS)};
    for (int i = 0; i < uConv.size(); i++) {
        uConv[i] = polyExpand(x, i);
    }
    for (int i = 0; i < chebyPolys.size(); i++) {
        std::vector<double> intermediate(chebyPolys[i].size(), 0.0);
        for (int j = 0; j < chebyPolys[i].size(); j++) {
            intermediate = vAddV(intermediate, vMultiply(uConv[j], chebyPolys[i][j]));
        }
        convPolys.push_back(intermediate);
    }
    for (int i = 0; i < coeffs.size(); i++) {
        std::vector<double> temp = vMultiply(convPolys[i], coeffs[i]);
        result = vAddV(result, temp);
    }
    return result;
}

//Approximation function
std::vector<double> polyApprox(double (*func)(double), int degree, double intervalS, double intervalE) {
    degree += 1;
    std::vector<std::vector<double>> chebyPolys;
    for (int i = 0; i < degree; i++) {
        chebyPolys.push_back(chebyRec(i, 1));
    }
    std::vector<double> roots = calcRoots(degree);
    std::vector<double> xs = vAdd(vMultiply(roots, (intervalE-intervalS)/2), (intervalE+intervalS)/2);
    std::vector<double> ys = vApply(xs, func);
    // printV(roots);
    // printV(xs);
    // printV(ys);
    std::vector<double> coeffs = {};
    for (int i = 0; i < degree; i++) {
        if (i == 0) {
            coeffs.push_back(vAvrg(ys));
        } else {
            coeffs.push_back(coeffEval(ys, chebyPolys[i], roots, degree));
        }
    }
    return truncate(coeffs, chebyPolys, intervalS, intervalE);
}

//---------------------------------------------------------------------------------------------------------------------------------------------
//Approximation Error Calculation

//Calculate Max Approximation Error:

//this constant determines the number points checked for the max approx error
constexpr double APPROX_ERROR_SCALE = 1.0/1000.0;

//get max approxError
double getMaxApproxError(std::vector<double> approxFunc, double (*func)(double), double intervalS, double intervalE) {
    double maxError = 0;
    for (int i = intervalS; i < intervalE; i = i + APPROX_ERROR_SCALE) {
        double approxVal = polyEval(approxFunc, i);
        double originalVal = func(i);
        double error = std::abs(originalVal - approxVal);
        if (error > maxError) {
            maxError = error;
        }
    }
    return maxError;
}

double getMeanApproxError(std::vector<double> approxFunc, double (*func)(double), double intervalS, double intervalE) {
    double meanError = 0;
    for (int i = intervalS; i < intervalE; i = i + APPROX_ERROR_SCALE) {
        double approxVal = polyEval(approxFunc, i);
        double originalVal = func(i);
        double error = std::abs(originalVal - approxVal) * APPROX_ERROR_SCALE;
        meanError += error;
    }
    return meanError;
}

//---------------------------------------------------------------------------------------------------------------------------------------------

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

int main() {
    //set params
    CCParams<CryptoContextCKKSRNS> params;
    params.SetPlaintextModulus(257); // p
    params.SetRingDim(128); // n =  m/2
    params.SetMultiplicativeDepth(5); // no. q
    params.SetMaxRelinSkDeg(3);
    params.SetSecurityLevel(HEStd_NotSet);

    //enable features
    CryptoContext<DCRTPoly> cc = GenCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);

    //generate keys
    auto keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);

    //Approximate function
    std::vector<double> approxActivation = polyApprox(&test, 3, -1, 1);
    printV(approxActivation);

    //poly eval
    std::vector<std::complex<double>> vector = {1,2,3,4};
    std::vector<double> coeffs = approxActivation;
    auto cipher = toPolyCC(cc, keys, vector, coeffs);

    //check if correct
    Plaintext result;
    cc->Decrypt(keys.secretKey, cipher, &result);
    result->SetLength(vector.size());
    std::cout << "Result is:" << std::endl;
    std::cout << result << std::endl;

    return 0;

}