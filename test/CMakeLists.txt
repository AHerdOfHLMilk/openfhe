add_executable (tests MatrixVectorMultiplicationTest.cc)
target_link_libraries(matvecmult HE_LLM -pthread -lz)