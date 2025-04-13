cmake_minimum_required(VERSION 3.10)
project(candbox VERSION 0.0.1)

file(GLOB CANDBOX_SRCS CMAKE_CONFIGURE_DEPENDS "src/candbox.cpp" "src/syscall_mapper.cpp" "src/syscall_rule.cpp")
file(GLOB CANDBOX_HEADERS CMAKE_CONFIGURE_DEPENDS "include/candbox/*.h")

find_package(PkgConfig REQUIRED)

pkg_check_modules(SECCOMP REQUIRED libseccomp)

include(GNUInstallDirs)

add_library(candbox SHARED ${CANDBOX_SRCS} ${CANDBOX_HEADERS})

target_include_directories(candbox PUBLIC
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>"
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
)
target_link_libraries(candbox PRIVATE ${SECCOMP_LIBRARIES})

install(TARGETS candbox
    EXPORT candbox
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

### build
install(EXPORT candbox 
    FILE candboxConfigTargets.cmake
    NAMESPACE candbox::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/candbox
)

include(CMakePackageConfigHelpers)

configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/candboxConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/candboxConfig.cmake"
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/candbox
)
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/candboxConfigVersion.cmake"
    VERSION 0.0.1
    COMPATIBILITY ExactVersion
)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/candboxConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/candboxConfigVersion.cmake"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/candbox
)
