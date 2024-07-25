add_library(HE_LLM
	internalTensor.cpp
	cipherTensor.cpp
)
target_include_directories(HE_LLM PUBLIC include)
target_link_libraries(HE_LLM OPENFHE_PKE OPENFHE_CORE OPENFHE_BIN -pthread -lz)