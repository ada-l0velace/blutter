set(BLUTTER_SOURCE_DIR "${PROJECT_SOURCE_DIR}/src")

add_executable(fresh_content_uses_test unit/fresh_content_uses_test.cpp
    "${BLUTTER_SOURCE_DIR}/FreshContentUses.cpp" "${BLUTTER_SOURCE_DIR}/FieldInputOrigins.cpp"
    "${BLUTTER_SOURCE_DIR}/CallInputShapes.cpp" "${BLUTTER_SOURCE_DIR}/CallInputRoles.cpp"
    "${BLUTTER_SOURCE_DIR}/Arm64Ir.cpp" "${BLUTTER_SOURCE_DIR}/NativeIr.cpp")
target_include_directories(fresh_content_uses_test PRIVATE "${BLUTTER_SOURCE_DIR}")
target_link_libraries(fresh_content_uses_test PRIVATE capstone)
blutter_instrument_test_target(fresh_content_uses_test)
add_test(NAME fresh_content_uses COMMAND fresh_content_uses_test)

add_executable(fresh_field_initializations_test unit/fresh_field_initializations_test.cpp
    "${BLUTTER_SOURCE_DIR}/FreshFieldInitializations.cpp" "${BLUTTER_SOURCE_DIR}/AsyncFieldAccesses.cpp"
    "${BLUTTER_SOURCE_DIR}/WordOrigins.cpp" "${BLUTTER_SOURCE_DIR}/Arm64Ir.cpp" "${BLUTTER_SOURCE_DIR}/NativeIr.cpp")
target_include_directories(fresh_field_initializations_test PRIVATE "${BLUTTER_SOURCE_DIR}")
target_link_libraries(fresh_field_initializations_test PRIVATE capstone)
blutter_instrument_test_target(fresh_field_initializations_test)
add_test(NAME fresh_field_initializations COMMAND fresh_field_initializations_test)

add_executable(captured_field_values_test unit/captured_field_values_test.cpp
    "${BLUTTER_SOURCE_DIR}/CapturedFieldValues.cpp" "${BLUTTER_SOURCE_DIR}/Arm64Ir.cpp"
    "${BLUTTER_SOURCE_DIR}/NativeIr.cpp")
target_include_directories(captured_field_values_test PRIVATE "${BLUTTER_SOURCE_DIR}")
target_link_libraries(captured_field_values_test PRIVATE capstone)
blutter_instrument_test_target(captured_field_values_test)
add_test(NAME captured_field_values COMMAND captured_field_values_test)

add_executable(field_input_origins_test unit/field_input_origins_test.cpp
    "${BLUTTER_SOURCE_DIR}/FieldInputOrigins.cpp" "${BLUTTER_SOURCE_DIR}/CallInputShapes.cpp"
    "${BLUTTER_SOURCE_DIR}/CallInputRoles.cpp")
target_include_directories(field_input_origins_test PRIVATE "${BLUTTER_SOURCE_DIR}")
target_link_libraries(field_input_origins_test PRIVATE capstone)
blutter_instrument_test_target(field_input_origins_test)
add_test(NAME field_input_origins COMMAND field_input_origins_test)

add_executable(async_field_accesses_test unit/async_field_accesses_test.cpp
    "${BLUTTER_SOURCE_DIR}/AsyncFieldAccesses.cpp" "${BLUTTER_SOURCE_DIR}/Arm64Ir.cpp"
    "${BLUTTER_SOURCE_DIR}/NativeIr.cpp")
target_include_directories(async_field_accesses_test PRIVATE "${BLUTTER_SOURCE_DIR}")
target_link_libraries(async_field_accesses_test PRIVATE capstone)
blutter_instrument_test_target(async_field_accesses_test)
add_test(NAME async_field_accesses COMMAND async_field_accesses_test)

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

add_executable(arm64_memory_test unit/arm64_memory_test.cpp)
target_include_directories(arm64_memory_test PRIVATE "${BLUTTER_SOURCE_DIR}")
target_link_libraries(arm64_memory_test PRIVATE capstone)
add_test(NAME arm64_memory COMMAND arm64_memory_test)
add_executable(async_contracts_test unit/async_contracts_test.cpp)
target_include_directories(async_contracts_test PRIVATE "${BLUTTER_SOURCE_DIR}")
blutter_instrument_test_target(async_contracts_test)
add_test(NAME async_contracts COMMAND async_contracts_test)
add_executable(async_origins_test unit/async_origins_test.cpp "${BLUTTER_SOURCE_DIR}/AsyncOrigins.cpp" "${BLUTTER_SOURCE_DIR}/WordOrigins.cpp"
    "${BLUTTER_SOURCE_DIR}/NativeIr.cpp" "${BLUTTER_SOURCE_DIR}/Arm64Ir.cpp")
target_include_directories(async_origins_test PRIVATE "${BLUTTER_SOURCE_DIR}")
target_link_libraries(async_origins_test PRIVATE capstone)
blutter_instrument_test_target(async_origins_test)
add_test(NAME async_origins COMMAND async_origins_test)

foreach(profile IN ITEMS upstream shorebird_3c9c shorebird_8399 shorebird_7d8f shorebird_26a7 shorebird_db65)
    add_executable(thread_layout_${profile}_test unit/thread_layout_test.cpp)
    target_include_directories(thread_layout_${profile}_test PRIVATE "${BLUTTER_SOURCE_DIR}")
    if(NOT profile STREQUAL "upstream")
        string(TOUPPER "BLUTTER_${profile}" profile_macro)
        target_compile_definitions(thread_layout_${profile}_test PRIVATE ${profile_macro})
    endif()
    blutter_instrument_test_target(thread_layout_${profile}_test)
    add_test(NAME thread_layout_${profile} COMMAND thread_layout_${profile}_test)

    add_executable(runtime_features_${profile}_test unit/runtime_features_test.cpp)
    target_include_directories(runtime_features_${profile}_test PRIVATE "${BLUTTER_SOURCE_DIR}")
    if(NOT profile STREQUAL "upstream")
        target_compile_definitions(runtime_features_${profile}_test PRIVATE ${profile_macro})
    endif()
    if(profile STREQUAL "shorebird_3c9c")
        target_compile_definitions(runtime_features_${profile}_test PRIVATE EXPECT_TABLE_SUPPORT=1)
    else()
        target_compile_definitions(runtime_features_${profile}_test PRIVATE EXPECT_TABLE_SUPPORT=0)
    endif()
    blutter_instrument_test_target(runtime_features_${profile}_test)
    add_test(NAME runtime_features_${profile} COMMAND runtime_features_${profile}_test)
endforeach()

add_executable(analysis_diagnostics_test unit/analysis_diagnostics_test.cpp)
target_include_directories(analysis_diagnostics_test PRIVATE "${BLUTTER_SOURCE_DIR}")

add_executable(snapshot_code_ranges_test unit/snapshot_code_ranges_test.cpp)
target_include_directories(snapshot_code_ranges_test PRIVATE "${BLUTTER_SOURCE_DIR}")
add_executable(native_payload_routing_test unit/native_payload_routing_test.cpp)
target_include_directories(native_payload_routing_test PRIVATE "${BLUTTER_SOURCE_DIR}")
add_test(NAME native_payload_routing COMMAND native_payload_routing_test)
add_executable(function_identity_index_test unit/function_identity_index_test.cpp)
target_include_directories(function_identity_index_test PRIVATE "${BLUTTER_SOURCE_DIR}")
add_test(NAME function_identity_index COMMAND function_identity_index_test)
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
add_executable(sdk_stub_returns_test unit/sdk_stub_returns_test.cpp
    "${BLUTTER_SOURCE_DIR}/ReceiverAnalysis.cpp" "${BLUTTER_SOURCE_DIR}/CallEffects.cpp"
    "${BLUTTER_SOURCE_DIR}/SdkStubResultAnalysis.cpp" "${BLUTTER_SOURCE_DIR}/CallResultContexts.cpp"
    "${BLUTTER_SOURCE_DIR}/NativeIr.cpp" "${BLUTTER_SOURCE_DIR}/Arm64Ir.cpp"
    "${BLUTTER_SOURCE_DIR}/ArrayLengthAnalysis.cpp" "${BLUTTER_SOURCE_DIR}/StackCheckAnalysis.cpp")
target_include_directories(sdk_stub_returns_test PRIVATE "${BLUTTER_SOURCE_DIR}")
target_link_libraries(sdk_stub_returns_test PRIVATE capstone)
add_test(NAME sdk_stub_returns COMMAND sdk_stub_returns_test)
add_executable(register_inputs_test unit/register_inputs_test.cpp
    "${BLUTTER_SOURCE_DIR}/ReceiverAnalysis.cpp" "${BLUTTER_SOURCE_DIR}/RegisterContexts.cpp"
	"${BLUTTER_SOURCE_DIR}/CallResultContexts.cpp"
    "${BLUTTER_SOURCE_DIR}/CallEffects.cpp" "${BLUTTER_SOURCE_DIR}/NativeIr.cpp"
    "${BLUTTER_SOURCE_DIR}/Arm64Ir.cpp" "${BLUTTER_SOURCE_DIR}/ArrayLengthAnalysis.cpp"
    "${BLUTTER_SOURCE_DIR}/StackCheckAnalysis.cpp")
target_include_directories(register_inputs_test PRIVATE "${BLUTTER_SOURCE_DIR}")
target_link_libraries(register_inputs_test PRIVATE capstone)
add_test(NAME register_inputs COMMAND register_inputs_test)
add_executable(call_input_roles_test unit/call_input_roles_test.cpp "${BLUTTER_SOURCE_DIR}/CallInputRoles.cpp" "${BLUTTER_SOURCE_DIR}/CallResultAnnotations.cpp" "${BLUTTER_SOURCE_DIR}/CallInputShapes.cpp")
target_include_directories(call_input_roles_test PRIVATE "${BLUTTER_SOURCE_DIR}")
target_link_libraries(call_input_roles_test PRIVATE capstone)
blutter_instrument_test_target(call_input_roles_test)
add_test(NAME call_input_roles COMMAND call_input_roles_test)
add_executable(call_result_annotations_test unit/call_result_annotations_test.cpp "${BLUTTER_SOURCE_DIR}/CallResultAnnotations.cpp" "${BLUTTER_SOURCE_DIR}/CallInputRoles.cpp" "${BLUTTER_SOURCE_DIR}/CallInputShapes.cpp")
target_include_directories(call_result_annotations_test PRIVATE "${BLUTTER_SOURCE_DIR}")
target_link_libraries(call_result_annotations_test PRIVATE capstone)
add_test(NAME call_result_annotations COMMAND call_result_annotations_test)



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
        arm64_patterns_test arm64_memory_test analysis_diagnostics_test snapshot_code_ranges_test native_payload_routing_test function_identity_index_test read_unaligned_test native_ir_test arm64_ir_test array_length_test stack_check_test entry_predicate_test native_returns_test sdk_stub_returns_test register_inputs_test call_result_annotations_test)
    blutter_instrument_test_target(${target})
endforeach()

add_executable(call_input_shapes_test unit/call_input_shapes_test.cpp "${BLUTTER_SOURCE_DIR}/CallInputShapes.cpp"
    "${BLUTTER_SOURCE_DIR}/CallResultAnnotations.cpp" "${BLUTTER_SOURCE_DIR}/CallInputRoles.cpp")
target_include_directories(call_input_shapes_test PRIVATE "${BLUTTER_SOURCE_DIR}")
target_link_libraries(call_input_shapes_test PRIVATE capstone)
blutter_instrument_test_target(call_input_shapes_test)
add_test(NAME call_input_shapes COMMAND call_input_shapes_test)

add_executable(word_origins_test unit/word_origins_test.cpp "${BLUTTER_SOURCE_DIR}/WordOrigins.cpp" "${BLUTTER_SOURCE_DIR}/CallInputOrigins.cpp"
    "${BLUTTER_SOURCE_DIR}/NativeIr.cpp" "${BLUTTER_SOURCE_DIR}/Arm64Ir.cpp")
target_include_directories(word_origins_test PRIVATE "${BLUTTER_SOURCE_DIR}")
target_link_libraries(word_origins_test PRIVATE capstone)
blutter_instrument_test_target(word_origins_test)
add_test(NAME word_origins COMMAND word_origins_test)

add_executable(completion_analysis_test unit/completion_analysis_test.cpp "${BLUTTER_SOURCE_DIR}/CompletionAnalysis.cpp"
    "${BLUTTER_SOURCE_DIR}/WordOrigins.cpp" "${BLUTTER_SOURCE_DIR}/NativeIr.cpp" "${BLUTTER_SOURCE_DIR}/Arm64Ir.cpp")
target_include_directories(completion_analysis_test PRIVATE "${BLUTTER_SOURCE_DIR}")
target_link_libraries(completion_analysis_test PRIVATE capstone)
blutter_instrument_test_target(completion_analysis_test)
add_test(NAME completion_analysis COMMAND completion_analysis_test)

add_executable(async_future_bindings_test unit/async_future_bindings_test.cpp
    "${BLUTTER_SOURCE_DIR}/AsyncFutureBindings.cpp" "${BLUTTER_SOURCE_DIR}/CompletionAnalysis.cpp"
    "${BLUTTER_SOURCE_DIR}/WordOrigins.cpp" "${BLUTTER_SOURCE_DIR}/NativeIr.cpp" "${BLUTTER_SOURCE_DIR}/Arm64Ir.cpp")
target_include_directories(async_future_bindings_test PRIVATE "${BLUTTER_SOURCE_DIR}")
target_link_libraries(async_future_bindings_test PRIVATE capstone)
blutter_instrument_test_target(async_future_bindings_test)
add_test(NAME async_future_bindings COMMAND async_future_bindings_test)

add_executable(saved_async_references_test unit/saved_async_references_test.cpp
    "${BLUTTER_SOURCE_DIR}/SavedAsyncReferences.cpp" "${BLUTTER_SOURCE_DIR}/AsyncFutureBindings.cpp"
    "${BLUTTER_SOURCE_DIR}/CompletionAnalysis.cpp" "${BLUTTER_SOURCE_DIR}/WordOrigins.cpp"
    "${BLUTTER_SOURCE_DIR}/NativeIr.cpp" "${BLUTTER_SOURCE_DIR}/Arm64Ir.cpp")
target_include_directories(saved_async_references_test PRIVATE "${BLUTTER_SOURCE_DIR}")
target_link_libraries(saved_async_references_test PRIVATE capstone)
blutter_instrument_test_target(saved_async_references_test)
add_test(NAME saved_async_references COMMAND saved_async_references_test)
add_executable(callee_entry_reads_test unit/callee_entry_reads_test.cpp
    "${BLUTTER_SOURCE_DIR}/CalleeEntryReads.cpp" "${BLUTTER_SOURCE_DIR}/StackCheckAnalysis.cpp"
    "${BLUTTER_SOURCE_DIR}/NativeIr.cpp" "${BLUTTER_SOURCE_DIR}/Arm64Ir.cpp")
target_include_directories(callee_entry_reads_test PRIVATE "${BLUTTER_SOURCE_DIR}")
target_link_libraries(callee_entry_reads_test PRIVATE capstone)
blutter_instrument_test_target(callee_entry_reads_test)
add_test(NAME callee_entry_reads COMMAND callee_entry_reads_test)

add_executable(joined_async_references_test unit/joined_async_references_test.cpp
    "${BLUTTER_SOURCE_DIR}/SavedAsyncReferences.cpp" "${BLUTTER_SOURCE_DIR}/AsyncFutureBindings.cpp"
    "${BLUTTER_SOURCE_DIR}/CompletionAnalysis.cpp" "${BLUTTER_SOURCE_DIR}/WordOrigins.cpp"
    "${BLUTTER_SOURCE_DIR}/NativeIr.cpp" "${BLUTTER_SOURCE_DIR}/Arm64Ir.cpp")
target_include_directories(joined_async_references_test PRIVATE "${BLUTTER_SOURCE_DIR}")
target_link_libraries(joined_async_references_test PRIVATE capstone)
blutter_instrument_test_target(joined_async_references_test)
add_test(NAME joined_async_references COMMAND joined_async_references_test)
