#!/bin/bash

rm -rf main
clang++ -std=c++11 -Wall main.cc -I ../../include -l pcre -o main_cpp

