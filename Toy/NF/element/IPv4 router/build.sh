#!/bin/bash

rm -rf main
clang++ -std=c++11 -Wall main.cc -I ../../include -o main_cpp
