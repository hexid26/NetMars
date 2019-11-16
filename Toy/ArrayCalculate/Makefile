all: CPU CPU_thread GPU
.PHONY: all
CPU: CPU.cpp Array.hpp
	g++ -g CPU.cpp -o CPU
CPU_thread: CPU_thread.cpp Array.hpp
	g++ -g CPU_thread.cpp -o CPU_thread -l pthread
GPU: GPU.cu Array.hpp
	nvcc -g GPU.cu -o GPU -I /usr/local/cuda/include
clean:
	rm -rf CPU
	rm -rf CPU_thread
	rm -rf GPU
