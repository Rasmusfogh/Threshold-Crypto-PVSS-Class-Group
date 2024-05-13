add_custom_target (benchs_build COMMAND ${CMAKE_COMMAND} -E sleep 0)
add_custom_target (benchs COMMAND ${CMAKE_COMMAND} -E sleep 0)
add_dependencies (benchs benchs_build)

### List of benchmarks
set ( BENCHS_LIST #benchmark_qclpvss
                  #benchmark_qclpvss2
                  #benchmark_sss
                  benchmark_bdkg
                  #benchmark_pvss_reshare
                  #benchmark_nizk
                  )

### Automatically create target and test from TESTS_LIST
foreach (bench ${BENCHS_LIST})
  add_executable (${bench}_build ${bench}.cpp)
  set_target_properties (${bench}_build PROPERTIES OUTPUT_NAME ${bench})
  target_link_libraries (${bench}_build bicycl project benchmark::benchmark)
  add_custom_target (${bench} COMMAND ${bench}_build --benchmark_out=${bench}_result.json 
                                                    --benchmark_out_format=json
                                                    --benchmark_counters_tabular=true
                      COMMENT "Running ${bench}")
  add_dependencies (benchs_build ${bench}_build)
  add_dependencies (benchs ${bench})
endforeach ()
