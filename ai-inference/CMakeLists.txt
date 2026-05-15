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
)

# ─── Find Dependencies ────────────────────────────────────────────────────────
find_package(Threads REQUIRED)

# nlohmann_json: try system package first, fall back to FetchContent.
# Ubuntu <22.04 ships nlohmann-json3-dev without CMake config files.
find_package(nlohmann_json QUIET)
if(NOT nlohmann_json_FOUND)
    message(STATUS "nlohmann_json not found via find_package — using FetchContent")
    include(FetchContent)
    FetchContent_Declare(
        nlohmann_json
        URL      https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
        URL_HASH SHA256=d6c65aca6b1ed68e7a182f4757257b107ae403032760ed6ef121c9d55e81757d
    )
    FetchContent_MakeAvailable(nlohmann_json)
endif()

# spdlog: same pattern — system first, FetchContent fallback.
find_package(spdlog QUIET)
if(NOT spdlog_FOUND)
    message(STATUS "spdlog not found via find_package — using FetchContent")
    include(FetchContent)
    FetchContent_Declare(
        spdlog
        URL      https://github.com/gabime/spdlog/archive/refs/tags/v1.13.0.tar.gz
        URL_HASH SHA256=534f2ee1a4dcbeb22249856edfb2be76a1cf4f708a20b0ac2ed090ee24cfdbc9
    )
    FetchContent_MakeAvailable(spdlog)
endif()

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
