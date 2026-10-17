cmake_minimum_required(VERSION 3.22)
project(PrismDetector LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(R ${CMAKE_CURRENT_SOURCE_DIR}/vendor/research)
add_library(prismdetector SHARED
    detector.cpp rules.cpp network_time.cpp
    ${R}/chain_closure_20261018/src/detection_chains.cpp
    ${R}/chain_closure_20261018/src/classes_jni.cpp
    ${R}/environment_memory/src/environment_memory.cpp
    ${R}/environment_memory/src/input_methods_jni.cpp
    ${R}/accessibility/src/accessibility_core.cpp
    ${R}/accessibility/src/accessibility_jni.cpp
    ${R}/accessibility/src/accessibility_monitor.cpp
    ${R}/accessibility/src/accessibility_env.cpp
    ${R}/device_identity/src/identity.cpp
    ${R}/device_identity/src/crypto.cpp
    ${R}/device_identity/src/android_adapter.cpp
    ${R}/src/observed_models.cpp
    ${R}/src/verified_helpers.cpp)
if(ANDROID_ABI STREQUAL "arm64-v8a")
    target_sources(prismdetector PRIVATE ${R}/chain_closure_20261018/src/android_collectors.cpp)
else()
    target_sources(prismdetector PRIVATE portable_collectors.cpp)
endif()
target_compile_options(prismdetector PRIVATE -Wall -Wextra -fvisibility=hidden -ffunction-sections -fdata-sections)
target_link_options(prismdetector PRIVATE -Wl,--gc-sections -Wl,-z,max-page-size=16384)
target_link_libraries(prismdetector PRIVATE android log dl)
