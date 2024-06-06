cmake_minimum_required(VERSION 3.19)
project(StockRank VERSION 0.1.0 LANGUAGES C CXX)

# C++ 표준 설정 (예: C++17 사용)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(CTest)
enable_testing()

# add_library(StockRank StockRank.cpp)
add_executable(StockRank StockRank.cpp)

# Homebrew의 일반 include 경로 추가
target_include_directories(StockRank PRIVATE "/opt/homebrew/include" "/opt/homebrew/Cellar/seal/4.1.1/include/SEAL-4.1")

# SEAL 라이브러리 링크 필요 시 추가
target_link_libraries(StockRank "/opt/homebrew/lib/libseal.dylib")

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
