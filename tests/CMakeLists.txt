set(BLUTTER_SOURCE_DIR "${PROJECT_SOURCE_DIR}/src")

add_executable(arm64_analyzer_test
    integration/arm64_analyzer_test.cpp
    "${BLUTTER_SOURCE_DIR}/Arm64GdtAnalysis.cpp"
    "${BLUTTER_SOURCE_DIR}/Arm64ClassIdAnalysis.cpp"
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

add_executable(snapshot_code_ranges_test unit/snapshot_code_ranges_test.cpp)
target_include_directories(snapshot_code_ranges_test PRIVATE "${BLUTTER_SOURCE_DIR}")
add_executable(read_unaligned_test unit/read_unaligned_test.cpp)
target_include_directories(read_unaligned_test PRIVATE "${BLUTTER_SOURCE_DIR}")

add_executable(native_ir_test unit/native_ir_test.cpp "${BLUTTER_SOURCE_DIR}/NativeIr.cpp")
target_include_directories(native_ir_test PRIVATE "${BLUTTER_SOURCE_DIR}")
add_executable(arm64_ir_test unit/arm64_ir_test.cpp "${BLUTTER_SOURCE_DIR}/NativeIr.cpp" "${BLUTTER_SOURCE_DIR}/Arm64Ir.cpp")
target_include_directories(arm64_ir_test PRIVATE "${BLUTTER_SOURCE_DIR}")
target_link_libraries(arm64_ir_test PRIVATE capstone)
add_test(NAME native_ir COMMAND native_ir_test)
add_test(NAME arm64_ir COMMAND arm64_ir_test)
add_executable(array_length_test unit/array_length_test.cpp "${BLUTTER_SOURCE_DIR}/ArrayLengthAnalysis.cpp"
    "${BLUTTER_SOURCE_DIR}/NativeIr.cpp" "${BLUTTER_SOURCE_DIR}/Arm64Ir.cpp")
target_include_directories(array_length_test PRIVATE "${BLUTTER_SOURCE_DIR}")
target_link_libraries(array_length_test PRIVATE capstone)
add_test(NAME array_length COMMAND array_length_test)
add_executable(stack_check_test unit/stack_check_test.cpp "${BLUTTER_SOURCE_DIR}/StackCheckAnalysis.cpp"
    "${BLUTTER_SOURCE_DIR}/NativeIr.cpp" "${BLUTTER_SOURCE_DIR}/Arm64Ir.cpp")
target_include_directories(stack_check_test PRIVATE "${BLUTTER_SOURCE_DIR}")
target_link_libraries(stack_check_test PRIVATE capstone)
add_test(NAME stack_check COMMAND stack_check_test)
add_executable(entry_predicate_test unit/entry_predicate_test.cpp "${BLUTTER_SOURCE_DIR}/NativeIr.cpp" "${BLUTTER_SOURCE_DIR}/Arm64Ir.cpp")
target_include_directories(entry_predicate_test PRIVATE "${BLUTTER_SOURCE_DIR}")
target_link_libraries(entry_predicate_test PRIVATE capstone)
add_test(NAME entry_predicate COMMAND entry_predicate_test)
add_executable(native_returns_test unit/native_returns_test.cpp
    "${BLUTTER_SOURCE_DIR}/ReceiverAnalysis.cpp" "${BLUTTER_SOURCE_DIR}/CallEffects.cpp"
    "${BLUTTER_SOURCE_DIR}/NativeIr.cpp" "${BLUTTER_SOURCE_DIR}/Arm64Ir.cpp"
    "${BLUTTER_SOURCE_DIR}/ArrayLengthAnalysis.cpp" "${BLUTTER_SOURCE_DIR}/StackCheckAnalysis.cpp")
target_include_directories(native_returns_test PRIVATE "${BLUTTER_SOURCE_DIR}")
target_link_libraries(native_returns_test PRIVATE capstone)
add_test(NAME native_returns COMMAND native_returns_test)
add_executable(register_inputs_test unit/register_inputs_test.cpp
    "${BLUTTER_SOURCE_DIR}/ReceiverAnalysis.cpp" "${BLUTTER_SOURCE_DIR}/RegisterContexts.cpp"
	"${BLUTTER_SOURCE_DIR}/CallResultContexts.cpp"
    "${BLUTTER_SOURCE_DIR}/CallEffects.cpp" "${BLUTTER_SOURCE_DIR}/NativeIr.cpp"
    "${BLUTTER_SOURCE_DIR}/Arm64Ir.cpp" "${BLUTTER_SOURCE_DIR}/ArrayLengthAnalysis.cpp"
    "${BLUTTER_SOURCE_DIR}/StackCheckAnalysis.cpp")
target_include_directories(register_inputs_test PRIVATE "${BLUTTER_SOURCE_DIR}")
target_link_libraries(register_inputs_test PRIVATE capstone)
add_test(NAME register_inputs COMMAND register_inputs_test)



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
add_test(NAME snapshot_code_ranges COMMAND snapshot_code_ranges_test)
add_test(NAME read_unaligned COMMAND read_unaligned_test)

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

foreach(target arm64_analyzer_test arm64_decoder_test arm64_boxing_test
        arm64_patterns_test analysis_diagnostics_test snapshot_code_ranges_test read_unaligned_test native_ir_test arm64_ir_test array_length_test stack_check_test entry_predicate_test native_returns_test register_inputs_test)
    blutter_instrument_test_target(${target})
endforeach()
