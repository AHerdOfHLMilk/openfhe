#include<algorithm>
#include<vector>
#include<cmath>
#include <iostream>

constexpr double pi = 3.14159265358979323846;

double test(double val) {
    return std::cos(val);
}

double ReLU(double val) {
    return std::max((double) 0, val);
}

double leakyReLU(double val) {
    return std::max((double) 0.01*val, val);
}

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

std::vector<double> vAdd(std::vector<double> v, double additive) {
    std::vector<double> result(v);
    for (int i = 0; i < v.size(); i++) {
        result[i] += additive;
    }
    return result;
}

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

std::vector<double> calcRoots(int degree) {
    std::vector<double> result;
    for (int i = 1; i < degree+1; i++) {
        double temp = ((2.0*i - 1.0) * pi)/(2.0*degree);
        result.push_back(-std::cos(temp));
    }
    return result;
}

double polyEval(std::vector<double> term, double x) {
    double result = 0.0;
    for (int i = 0; i < term.size(); i++) {
        result += term[i] * pow(x, i);
    }
    return result;
}

std::vector<double> polyMultiply(std::vector<double> p1, std::vector<double> p2) {
    std::vector<double> result(p1.size()*p2.size(), 0.0);
    for (int i = 0; i < p1.size(); i++) {
        for (int j = 0; j < p2.size(); j++) {
            result[i+j] = result[i+j] + (p1[i] * p2[j]);
        }
    }
    return result;
}

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

std::vector<double> calcTerm(std::vector<double> term, std::vector<double> roots) {
    std::vector<double> result(roots);
    for (int i = 0; i < roots.size(); i++) {
        result[i] = polyEval(term, roots[i]);
    }
    return result;
}

double coeffEval(std::vector<double> ys, std::vector<double> term, std::vector<double> roots, int degree) {
    auto temp = calcTerm(term, roots);
    auto temp2 = vMultiplyV(temp, ys);
    double result = 2 * vSum(temp2)/degree;
    return result;
}

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

std::vector<double> polyApprox(double (*func)(double), int degree, double intervalS, double intervalE) {
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
    for (int i = 0; i < degree+1; i++) {
        if (i == 0) {
            coeffs.push_back(vAvrg(ys));
        } else {
            coeffs.push_back(coeffEval(ys, chebyPolys[i], roots, degree));
        }
    }
    return truncate(coeffs, chebyPolys, intervalS, intervalE);
}

int main() {
    std::vector<double> coeff = polyApprox(&test, 5, -1, 1);
    printV(coeff);
}