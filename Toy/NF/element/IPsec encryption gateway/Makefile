main_cpp: main.cpp
	nvcc -g main.cpp IPsecAES_GPU.cu IPsecAuthHMACSHA1_GPU.cu -o main_cpp -I ../../include -I /usr/local/cuda/include -I /usr/local/cuda/samples/common/inc -l ssl -l crypto -L /usr/local/cuda/lib64 -L /usr/local/cuda/samples/common/lib
clean:
	rm -rf main_cpp