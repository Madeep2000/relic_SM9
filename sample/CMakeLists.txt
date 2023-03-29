# CMakeLists.txt
macro(ADD_SAMPLE MODULE)
	add_executable(sample_${MODULE} sample_${MODULE}.c common.c)
	if (STLIB)
		target_link_libraries(sample_${MODULE} ${RELIC_S})
	else(STLIB)
		if (SHLIB)
			target_link_libraries(sample_${MODULE} ${RELIC})
		endif(SHLIB)
	endif(STLIB)
	# add_test(test_${MODULE} ${SIMUL} ${SIMAR} ${EXECUTABLE_OUTPUT_PATH}/test_${MODULE})
endmacro(ADD_SAMPLE)


if (WITH_CP)
    ADD_SAMPLE(ecdsa)
endif(WITH_CP)