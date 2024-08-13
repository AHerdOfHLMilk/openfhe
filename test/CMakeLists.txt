add_executable (tests MatrixVectorMultiplication.cpp)
target_link_libraries(matvecmult HE_LLM -pthread -lz)