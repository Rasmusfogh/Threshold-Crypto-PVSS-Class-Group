# Set the source files for your project in the "src" folder
set(SRC_SOURCE_FILES
    qclpvss.cpp
    utils/qclpvss_utils.cpp
    utils/sss.cpp
    utils/openssl_hash_ext.cpp
    utils/secp256k1_wrapper.cpp
    utils/datatype.cpp
    nizk/nizkpok_dl.cpp
    nizk/nizk_sh.cpp
    nizk/nizk_dleq.cpp
)

# Create a library target for your project
add_library(project ${SRC_SOURCE_FILES})

# Link the bicycl library to your project
target_link_libraries(project PUBLIC bicycl libsecp256k1::secp256k1)

# Optionally, specify any include directories needed for your project
target_include_directories(project PUBLIC 
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/application
    ${CMAKE_CURRENT_SOURCE_DIR}/utils
    ${CMAKE_CURRENT_SOURCE_DIR}/nizk)

# Optionally, specify any additional compiler options or flags
# target_compile_options(project PRIVATE ...)

# Optionally, add any other dependencies or configurations needed for your project
