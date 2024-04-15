include (CTest)
if ("${CMAKE_GENERATOR}" STREQUAL "Unix Makefiles")
  set (_cmd ${CMAKE_CTEST_COMMAND} --output-on-failure $(ARGS))
else ()
  set (_cmd ${CMAKE_CTEST_COMMAND} --output-on-failure)
endif ()
add_custom_target (tests COMMAND ${_cmd} COMMENT "Running the tests")

### List of tests
set (TESTS_LIST #test_qclpvss
                #test_sss
                #test_nizkpok_dl
                #test_bdkg
                #test_nizk_linear_cl
                test_pvss_reshare
                )

### Automatically create target and test from TESTS_LIST
foreach (test ${TESTS_LIST})
  # /!\ The test and the target building the executable have the same name
  add_executable (${test} ${test}.cpp)
  target_link_libraries (${test} PUBLIC bicycl project)
  add_dependencies (tests ${test})
  add_test (NAME ${test} COMMAND ${test}
                         WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
endforeach ()
