#pragma once

#include <fstream>
#include <iostream>
#include <string>
#define ARRAY_SIZE 24000
// 14000
class Array {
 public:
  int data[ARRAY_SIZE][ARRAY_SIZE];
  Array() {
    for (int i = 0; i < ARRAY_SIZE; i++) {
      for (int j = 0; j < ARRAY_SIZE; j++) {
        data[i][j] = -9999;
      }
    }
  }
  Array(const Array &ar) {
    for (int i = 0; i < ARRAY_SIZE; i++) {
      for (int j = 0; j < ARRAY_SIZE; j++) {
        data[i][j] = ar.data[i][j];
      }
    }
  }
  void GeneraFromRand() {
    for (int i = 0; i < ARRAY_SIZE; i++) {
      for (int j = 0; j < ARRAY_SIZE; j++) {
        data[i][j] = rand() % 100;
      }
    }
  }
  void GeneraFromFile(std::string filename) {
    std::ifstream read(filename);
    for (int i = 0; i < ARRAY_SIZE; i++) {
      for (int j = 0; j < ARRAY_SIZE; j++) {
        read >> data[i][j];
      }
    }
    read.close();
  }
  void PrintToFile(std::string filename) {
    std::ofstream save(filename, std::ios_base::trunc);
    for (int i = 0; i < ARRAY_SIZE; i++) {
      for (int j = 0; j < ARRAY_SIZE; j++) {
        save << data[i][j];
        if (j == ARRAY_SIZE - 1) {
          save << "\n";
        } else {
          save << " ";
        }
      }
    }
    save.close();
  }
};
Array *ar = new Array[3];