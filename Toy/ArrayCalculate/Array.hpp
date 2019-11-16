#pragma once
#include <iostream>
#include <string>
#include <fstream>
#define array_size 14000
//14000
class Array
{
public:
    int data[array_size][array_size];
    Array()
    {
        for (int i = 0; i < array_size; i++)
        {
            for (int j = 0; j < array_size; j++)
            {
                data[i][j] = -9999;
            }
        }
    }
    Array(const Array &ar)
    {
        for (int i = 0; i < array_size; i++)
        {
            for (int j = 0; j < array_size; j++)
            {
                data[i][j] = ar.data[i][j];
            }
        }
    }
    void GeneraFromRand()
    {
        for (int i = 0; i < array_size; i++)
        {
            for (int j = 0; j < array_size; j++)
            {
                data[i][j] = rand() % 100;
            }
        }
    }
    void GeneraFromFile(std::string filename)
    {
        std::ifstream read(filename);
        for (int i = 0; i < array_size; i++)
        {
            for (int j = 0; j < array_size; j++)
            {
                read >> data[i][j];
            }
        }
        read.close();
    }
    void PrintToFile(std::string filename)
    {
        std::ofstream save(filename, std::ios_base::trunc);
        for (int i = 0; i < array_size; i++)
        {
            for (int j = 0; j < array_size; j++)
            {
                save << data[i][j];
                if (j == array_size - 1)
                {
                    save << "\n";
                }
                else
                {
                    save << " ";
                }
            }
        }
        save.close();
    }
};
Array *ar = new Array[3];