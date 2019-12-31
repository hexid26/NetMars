IPsec: IPsec.cpp
	nvcc -g IPsec.cpp IPsecAES_GPU.cu IPsecAuthHMACSHA1_GPU.cu -o IPsec -I ../../include -I /usr/local/cuda/include -l crypto -L /usr/local/cuda/lib64
clean:
	rm -rf IPsec
