INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR})

SET(sources
	pppoe.c
	mac_filter.c
	dpado.c
	cli.c
	disc.c

	vpppoe.c
)

IF (RADIUS)
SET(sources ${sources} tr101.c)
ENDIF(RADIUS)

ADD_LIBRARY(pppoe SHARED ${sources})

target_include_directories(pppoe PRIVATE /home/Dev/Work/vpp/build-root/install-vpp_debug-native/vpp/include)
target_link_directories(pppoe PRIVATE /home/Dev/Work/vpp/build-root/install-vpp_debug-native/vpp/lib/x86_64-linux-gnu/)

TARGET_LINK_LIBRARIES(pppoe vlan-mon connlimit vlibapi vlib vapiclient vppapiclient vlibmemory vppcom vlibapi vlibmemoryclient vlibmemory vppinfra)
set_property(TARGET pppoe PROPERTY CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)
set_property(TARGET pppoe PROPERTY INSTALL_RPATH ${CMAKE_INSTALL_PREFIX}/lib${LIB_SUFFIX}/accel-ppp)

INSTALL(TARGETS pppoe LIBRARY DESTINATION lib${LIB_SUFFIX}/accel-ppp)
