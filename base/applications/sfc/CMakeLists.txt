
project(sfc)

include_directories(${REACTOS_SOURCE_DIR}/sdk/lib/conutils)

add_executable(sfc.exe sfc.c resource.h sfc.rc)
set_module_type(sfc.exe win32cui UNICODE)
target_link_libraries(sfc.exe conutils ${PSEH_LIB})
set_target_properties(sfc.exe PROPERTIES SUFFIX "")
add_importlibs(sfc.exe msvcrt kernel32 advapi32)
add_cd_file(TARGET sfc.exe DESTINATION reactos/system32 FOR all)
