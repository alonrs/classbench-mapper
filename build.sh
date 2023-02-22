#!/bin/bash

mkdir build -p 2>/dev/null
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . -j