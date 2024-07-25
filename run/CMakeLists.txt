add_executable (matvecmult MatrixVectorMultiplication.cpp)
target_link_libraries(matvecmult HE_LLM -pthread -lz)