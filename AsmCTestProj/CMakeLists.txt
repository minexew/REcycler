cmake_minimum_required(VERSION 3.16)
project(AsmCTestProj)

set(CMAKE_CXX_STANDARD 17)

add_executable(AsmCTestProj
        main.c
        AsmC-common.c
        AsmC-common.h
        AsmC-GPL.c
        AsmC-x86-32.c
        AsmC-x86-32.h
        ../Heroes3.project/AsmC/bb-table.c
        ../Heroes3.project/AsmC/info.c
        ../Heroes3.project/AsmC/program.c
        )

target_include_directories(AsmCTestProj PRIVATE ${CMAKE_CURRENT_LIST_DIR})
