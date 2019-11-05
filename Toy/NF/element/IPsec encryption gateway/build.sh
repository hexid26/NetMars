#!/bin/bash

rm -rf main
clang++ -std=c++11 -Wall main.cc -I ../../include -l ssl -l crypto -o main_cpp
