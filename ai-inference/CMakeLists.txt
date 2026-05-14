# =============================================================================
# Project: FALX V2
# Lead Architect & Owner: FT-1
# Description: CMake build definition for the C++ AI inference engine.
#              Links against gRPC, Protobuf, and optionally ONNX Runtime
#              for ML model inference. Phase 9 populates the AI logic.
# =============================================================================

cmake_minimum_required(VERSION 3.20)
project(falx-ai VERSION 0.1.0 LANGUAGES CXX)

# ─── C++ Standard ────────────────────────────────────────────────────────────
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ─── Build Type ───────────────────────────────────────────────────────────────
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# ─── Compiler Flags ───────────────────────────────────────────────────────────
add_compile_options(
    -Wall -Wextra -Wpedantic
    -Wno-unused-parameter
    $<$<CONFIG:Release>:-O3 -march=native -DNDEBUG>
    $<$<CONFIG:Debug>:-O0 -g -fsanitize=address,undefined>
)

# ─── Find Dependencies ────────────────────────────────────────────────────────
find_package(Threads      REQUIRED)
find_package(nlohmann_json REQUIRED)
find_package(spdlog        REQUIRED)

# Optional: ONNX Runtime for ML model inference
find_package(onnxruntime QUIET)

# ─── Protobuf / gRPC Sources ─────────────────────────────────────────────────
set(PROTO_FILES
    ${CMAKE_SOURCE_DIR}/../ipc/proto/falx.proto
)

# Phase 9 will call protoc here. Scaffold only for now.

# ─── Source Files ─────────────────────────────────────────────────────────────
set(AI_SOURCES
    src/main.cpp
    src/inference_engine.cpp
    src/ipc_client.cpp
)

# ─── Executable ───────────────────────────────────────────────────────────────
add_executable(falx-ai ${AI_SOURCES})

target_link_libraries(falx-ai
    PRIVATE
        Threads::Threads
        nlohmann_json::nlohmann_json
        spdlog::spdlog
        $<$<BOOL:${onnxruntime_FOUND}>:onnxruntime::onnxruntime>
)

target_include_directories(falx-ai
    PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_BINARY_DIR}
)

# ─── Install ──────────────────────────────────────────────────────────────────
install(TARGETS falx-ai RUNTIME DESTINATION bin)

# ─── Metadata ─────────────────────────────────────────────────────────────────
message(STATUS "FALX V2 AI Engine | Architect: FT-1 | Build: ${CMAKE_BUILD_TYPE}")
