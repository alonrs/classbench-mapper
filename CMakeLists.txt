cmake_minimum_required(VERSION 3.10)

project(ClassbenchMapper LANGUAGES CXX)

# Set custom debug and release flags
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -O0 -march=native")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O2 -march=native \
                             -DNDEBUG -flto")

# Set a default build type if none was specified
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

add_executable(util-cb.exe src/arguments.cpp src/log.cpp src/ruleset.cpp
               src/main.cpp)
target_include_directories(util-cb.exe PRIVATE ${PROJECT_SOURCE_DIR})
target_link_libraries(util-cb.exe pthread z)