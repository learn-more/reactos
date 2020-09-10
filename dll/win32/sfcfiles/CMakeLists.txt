
project(sfc)

spec2def(sfcfiles.dll sfcfiles.spec)

list(APPEND SOURCE
    sfcfiles.c
    ${CMAKE_CURRENT_BINARY_DIR}/sfcfiles_stubs.c
    ${CMAKE_CURRENT_BINARY_DIR}/sfcfiles.def)

add_library(sfcfiles MODULE ${SOURCE})
set_module_type(sfcfiles win32dll UNICODE ENTRYPOINT 0)
add_importlibs(sfcfiles ntdll)
add_cd_file(TARGET sfcfiles DESTINATION reactos/system32 FOR all)
