#ifndef CHEBYSHEV   // To make sure you don't declare the function more than once by including the header multiple times.
#define CHEBYSHEV

#include<algorithm>
#include<vector>
#include<cmath>
#include <iostream>
#include "openfhe.h"
#include <cstdlib>
#include <math.h>
#include <ctype.h>
#include <string>

std::vector<double> polyApprox(double (*func)(double), int degree, double intervalS, double intervalE);

#endif