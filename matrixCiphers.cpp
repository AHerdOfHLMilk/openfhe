#include <vector>
#include "openfhe.h"
#include <string>

using namespace lbcrypto;

//Function to print out contents of a vector
void printV(std::vector<double> v) {
    for (auto i : v) {
        std::cout << i << ",";
    }
    std::cout << std::endl;
}

std::vector<double> concatV (std::vector<double> vector1, std::vector<double> vector2) {
    vector1.insert(vector1.end(), vector2.begin(), vector2.end());
    return vector1;
}

class cMatrix {
        private:
        std::vector<std::vector<double>> matrix;
        unsigned int row;
        unsigned int col;

        public:
        cMatrix() {
            this->matrix = {};
            this->row = 0;
            this->col = 0;
        }

        cMatrix(unsigned int x, unsigned int y) {
            //default value is 0
            matrix.resize(x, std::vector<double>(y, 0.0)); 
            this->row = x;
            this->col = y;
        }

        cMatrix(std::vector<std::vector<double>> m, unsigned int slotsize) { //slotsize needa be implemented ####################
            this->matrix = {};
            this->row = m.size();
            this->col = slotsize;
            for (auto v : m) {
                auto temp = std::vector<double>(v);
                temp.resize(slotsize, 0.0); //auto pad any row of matrix without enough elements with 0s
                matrix.push_back(temp);
            }
        }

        std::vector<std::vector<double>> getMatrix() {
            return std::vector<std::vector<double>>(matrix);
        }

        unsigned int getcol() {
            return this->col;
        }

        unsigned int getrow() {
            return this->row;
        }

        std::vector<double> getRow(unsigned int pos) {
            return this->matrix[pos];
        }

        double getElem(unsigned int posX, unsigned int posY) {
            return getRow(posX)[posY];
        }

        void set(unsigned int posX, unsigned int posY, double val) {
            matrix[posX][posY] = val;
        }

    };

class matrix {

//Internal matrix structure
    public:

//need to take in num of slots to know how many matrices can be fit into the plaintext
//this class should be just the packing of the matrices, encryption etc can be pulled out
    //External facing matrix structure
    private: 
    cMatrix m;
    cMatrix col;
    cMatrix diag; //diagPacking (rename the var names to be longer and easier to understand)
    Plaintext pt;
    std::vector<Plaintext> ptVector = {};
    Ciphertext<DCRTPoly> ct;
    CryptoContext<DCRTPoly> cc;
    bool CCinit = false;

    public:
    matrix(unsigned int x, unsigned int y) {
        this->m = cMatrix(x,y);
    }

    matrix(cMatrix m) {
        this->m = m;
    }

    matrix(std::vector<std::vector<double>> m) {
        this->m = cMatrix(m);
    }

    void setCryptoContext(CryptoContext<DCRTPoly> cc) {
        this->cc = cc;
        this->CCinit = true;
    }

    void loadCol() {
        cMatrix col = cMatrix(m.getrow(), m.getcol());
        for (int i = 0; i < m.getrow(); i++) {
            for (int j = 0; j < m.getcol(); j++) {
                col.set(i, j, m.getElem(j, i));
            }
        }
        this->col = col;
    }

    void loadDiag() {
        if (m.getrow() != m.getcol()) {
            throw "Non-square matrix";
        }
        cMatrix diag = cMatrix(m.getrow(), m.getcol());
        for (int i = 0; i < m.getrow(); i++) {
            for (int j = 0; j < m.getcol(); j++) {
                diag.set(j, i, m.getElem(i, (j+i) % m.getcol()));
            }
        }
        this->diag = diag;
    }

    void packRowPlainText() {
        if (CCinit == false) {
            throw "Crypto context not given";
        }
        for (auto v : m.getMatrix()) {
            ptVector.push_back(cc->MakeCKKSPackedPlaintext(v));
        }
    }

    void packColPlainText() {
        if (CCinit == false) {
            throw "Crypto context not given";
        }
        loadCol();
        for (auto v : col.getMatrix()) {
            printV(v);
            ptVector.push_back(cc->MakeCKKSPackedPlaintext(v));
        }
    }

    void packDiagPlainText() {
        if (CCinit == false) {
            throw "Crypto context not given";
        }
        try {
            loadDiag();
        } catch (char const* err) {
            std::cout << err << std::endl;
        }
        for (auto v : diag.getMatrix()) {
            ptVector.push_back(cc->MakeCKKSPackedPlaintext(v));
        }
    }

    void packParallelRowPlainText() {
        std::vector<double> result = {};
        for (auto row : m.getMatrix()) {
            if (result.size() == 0) {
                result = row;
            }
            concatV(result, row);
        }
        this->pt = cc->MakeCKKSPackedPlaintext(result);
    }

    void packParallelColPlainText() {
        std::vector<double> result = {};
        for (auto row : col.getMatrix()) {
            if (result.size() == 0) {
                result = row;
            }
            concatV(result, row);
        }
        this->pt = cc->MakeCKKSPackedPlaintext(result);
    }

    void packParallelDiagPlainText() {
        std::vector<double> result = {};
        for (auto row : diag.getMatrix()) {
            if (result.size() == 0) {
                result = row;
            }
            concatV(result, row);
        }
        this->pt = cc->MakeCKKSPackedPlaintext(result);
        std::cout << pt << std::endl;
    }



};

int main() {
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

    auto m1 = cMatrix({{1,2,3}, {4,5,6}, {7,8,9}});

    auto m = matrix({{1,2,3}, {4,5,6}, {7,8,9}});
    m.setCryptoContext(cc);
    try {
        m.packParallelDiagPlainText();
    } catch (char const* err) {
        std::cout << err << std::endl;
    }
}
