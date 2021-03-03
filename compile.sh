#!/bin/bash

mkdir -p build/bin
mkdir -p build/obj

g++ -I./include -c ./src/ChaCha.cpp -o ./build/obj/chacha.o -std=c++17
ar r ./build/bin/chachalib.a ./build/obj/chacha.o
ranlib ./build/bin/chachalib.a