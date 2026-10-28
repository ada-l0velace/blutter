set(BLUTTER_SOURCE_DIR "${PROJECT_SOURCE_DIR}/src")

add_executable(arm64_analyzer_test
    integration/arm64_analyzer_test.cpp
    "${BLUTTER_SOURCE_DIR}/Arm64GdtAnalysis.cpp"
    "${BLUTTER_SOURCE_DIR}/Disassembler.cpp"
    "${BLUTTER_SOURCE_DIR}/Disassembler_arm64.cpp"
    "${BLUTTER_SOURCE_DIR}/VarValue.cpp")
target_include_directories(arm64_analyzer_test PRIVATE "${BLUTTER_SOURCE_DIR}")
target_link_libraries(arm64_analyzer_test PRIVATE ${DARTLIB} capstone)
target_compile_definitions(arm64_analyzer_test PRIVATE ${defines})
target_compile_options(arm64_analyzer_test PRIVATE ${cc_opts})
target_precompile_headers(arm64_analyzer_test PRIVATE "${BLUTTER_SOURCE_DIR}/pch.h")

add_executable(arm64_decoder_test integration/arm64_decoder_test.cpp
    "${BLUTTER_SOURCE_DIR}/Disassembler.cpp"
    "${BLUTTER_SOURCE_DIR}/Disassembler_arm64.cpp")
target_include_directories(arm64_decoder_test PRIVATE "${BLUTTER_SOURCE_DIR}")
target_link_libraries(arm64_decoder_test PRIVATE ${DARTLIB} capstone)
target_compile_definitions(arm64_decoder_test PRIVATE ${defines})
target_compile_options(arm64_decoder_test PRIVATE ${cc_opts})
target_precompile_headers(arm64_decoder_test PRIVATE "${BLUTTER_SOURCE_DIR}/pch.h")

add_executable(arm64_patterns_test unit/arm64_patterns_test.cpp)
target_include_directories(arm64_patterns_test PRIVATE "${BLUTTER_SOURCE_DIR}")
target_link_libraries(arm64_patterns_test PRIVATE capstone)

add_executable(analysis_diagnostics_test unit/analysis_diagnostics_test.cpp)
target_include_directories(analysis_diagnostics_test PRIVATE "${BLUTTER_SOURCE_DIR}")

add_test(NAME arm64_analyzer COMMAND arm64_analyzer_test)
add_test(NAME arm64_decoder COMMAND arm64_decoder_test)
add_executable(arm64_boxing_test integration/arm64_boxing_test.cpp
    "${BLUTTER_SOURCE_DIR}/Disassembler.cpp"
    "${BLUTTER_SOURCE_DIR}/Disassembler_arm64.cpp")
target_include_directories(arm64_boxing_test PRIVATE "${BLUTTER_SOURCE_DIR}")
target_link_libraries(arm64_boxing_test PRIVATE ${DARTLIB} capstone)
target_compile_definitions(arm64_boxing_test PRIVATE ${defines})
target_compile_options(arm64_boxing_test PRIVATE ${cc_opts})
target_precompile_headers(arm64_boxing_test PRIVATE "${BLUTTER_SOURCE_DIR}/pch.h")
add_test(NAME arm64_boxing COMMAND arm64_boxing_test)
add_test(NAME arm64_patterns COMMAND arm64_patterns_test)
add_test(NAME analysis_diagnostics COMMAND analysis_diagnostics_test)

function(expect_analysis_failure name target mode issue summary)
    add_test(NAME ${name} COMMAND "${CMAKE_COMMAND}"
        "-DTEST_EXECUTABLE=$<TARGET_FILE:${target}>" "-DTEST_MODE=${mode}"
        "-DEXPECTED_ISSUE=${issue}" "-DEXPECTED_SUMMARY=${summary}"
        -P "${CMAKE_CURRENT_SOURCE_DIR}/runners/expect_analysis_failure.cmake")
endfunction()

expect_analysis_failure(analysis_exports_with_errors analysis_diagnostics_test --probe-unsupported
    synthetic-unsupported "Analysis INCOMPLETE")
expect_analysis_failure(invalid_input_stops_export analysis_diagnostics_test --probe-invalid
    synthetic-invalid "Analysis FAILED")
expect_analysis_failure(unrecognized_dispatch_fails arm64_analyzer_test --probe-gdt
    unsupported-gdt-index "Analysis INCOMPLETE")

add_test(NAME invalid_input_prevents_export COMMAND "${CMAKE_COMMAND}"
    "-DTEST_EXECUTABLE=$<TARGET_FILE:${BINNAME}>"
    "-DTEST_DIRECTORY=${CMAKE_CURRENT_BINARY_DIR}/invalid-input-control"
    -P "${CMAKE_CURRENT_SOURCE_DIR}/runners/expect_input_failure.cmake")
