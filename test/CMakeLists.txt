macro(ADD_MODULE MODULE)
	
	SET(CMAKE_C_FLAGS "-O2 -fopenmp")
	add_executable(test_${MODULE} test_${MODULE}.c)
	if (STLIB)
		target_link_libraries(test_${MODULE} ${RELIC_S})
	else(STLIB)
		if (SHLIB)
			target_link_libraries(test_${MODULE} ${RELIC})
		endif(SHLIB)
	endif(STLIB)
	target_link_libraries(test_${MODULE} pthread)
	add_test(test_${MODULE} ${SIMUL} ${SIMAR} ${EXECUTABLE_OUTPUT_PATH}/test_${MODULE})
endmacro(ADD_MODULE)

if (CHECK)
	ADD_MODULE(err)
endif(CHECK)

if (WITH_BN)
	ADD_MODULE(bn)
endif(WITH_BN)

if (WITH_DV)
	ADD_MODULE(dv)
endif(WITH_DV)

if (WITH_FP)
	ADD_MODULE(fp)
endif(WITH_FP)

if (WITH_FPX)
	ADD_MODULE(fpx)
endif(WITH_FPX)

if (WITH_FB)
	ADD_MODULE(fb)
endif(WITH_FB)

if (WITH_FBX)
	ADD_MODULE(fbx)
endif(WITH_FBX)

if (WITH_EP)
	ADD_MODULE(ep)
endif(WITH_EP)

if (WITH_EPX)
	ADD_MODULE(epx)
endif(WITH_EPX)

if (WITH_EB)
	ADD_MODULE(eb)
endif(WITH_EB)

if (WITH_ED)
	ADD_MODULE(ed)
endif (WITH_ED)

if (WITH_EC)
	ADD_MODULE(ec)
endif(WITH_EC)

if (WITH_PC)
	ADD_MODULE(pc)
endif(WITH_PC)

if (WITH_PP)
	ADD_MODULE(pp)
endif(WITH_PP)

if (WITH_MD)
	ADD_MODULE(md)
endif(WITH_MD)

if (WITH_CP)
	ADD_MODULE(cp)
endif(WITH_CP)

if (WITH_MPC)
	ADD_MODULE(mpc)
endif(WITH_MPC)

# add module : test_sm9.c 
ADD_MODULE(sm9)

# add module : test_sm3.c 
ADD_MODULE(sm3)

# add module : test_sm9_sign.c 
ADD_MODULE(sm9_sign)

# add module : test_sm9_encrypt.c 
ADD_MODULE(sm9_encrypt)

# add module : test_sm9_server.c 
ADD_MODULE(sm9_server)

# add module : test_sm9_client.c 
ADD_MODULE(sm9_client)
# add module : test_sm9_kem.c 
ADD_MODULE(sm9_kem)
# add module : test_sm9_dh.c 
ADD_MODULE(sm9_dh)

#ADD_MODULE(sm9_revtcp)
#ADD_MODULE(sm9_tcp)

ADD_MODULE(rand)
ADD_MODULE(core)
# set (CMAKE_C_FLAGS " -O3 ${CMAKE_C_FLAGS}")