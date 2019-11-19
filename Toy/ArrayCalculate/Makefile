all: CPU CPU_thread GPU
.PHONY: all
CPU: CPU.cpp Array.hpp
	g++ -std=c++11  -Wall -O0 CPU.cpp -o CPU_cpp -lpthread
	g++ -std=c++11  -Wall -O3 CPU.cpp -o CPU_auto_optimize_cpp -lpthread
CPU_thread: CPU_thread.cpp Array.hpp
	g++ -std=c++11  -Wall -O3 CPU_thread.cpp -o CPU_thread_cpp -lpthread
GPU: GPU.cu Array.hpp
	nvcc -g GPU.cu -o GPU_cpp -I /usr/local/cuda/include
clean:
	rm -rf CPU_cpp
	rm -rf CPU_thread_cpp
	rm -rf GPU_cpp
