if(NOT DEFINED TEST_EXECUTABLE OR NOT DEFINED TEST_MODE OR NOT DEFINED EXPECTED_ISSUE OR NOT DEFINED EXPECTED_SUMMARY)
    message(FATAL_ERROR "A diagnostic executable, mode, issue and summary are required")
endif()

execute_process(COMMAND "${TEST_EXECUTABLE}" "${TEST_MODE}"
    RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE errors TIMEOUT 30)
if(NOT "${result}" STREQUAL "1")
    message(FATAL_ERROR "Expected exit 1, got ${result}: ${output}${errors}")
endif()
string(FIND "${output}${errors}" "Analysis error [${EXPECTED_ISSUE}]" issue_found)
string(FIND "${output}${errors}" "${EXPECTED_SUMMARY}" summary_found)
if(issue_found LESS 0 OR summary_found LESS 0)
    message(FATAL_ERROR "Missing expected analysis diagnostic: ${output}${errors}")
endif()
