# Set the source files for your project in the "src" folder
set(SRC_SOURCE_FILES
    qclpvss.cpp
    qclpvss_utils.cpp 
    nizkpok_dl.cpp
    # Add all your source files here
)

# Create a library target for your project
add_library(project ${SRC_SOURCE_FILES})

# Link the bicycl library to your project
target_link_libraries(project PUBLIC bicycl)

# Optionally, specify any include directories needed for your project
target_include_directories(project PUBLIC 
    ${CMAKE_CURRENT_SOURCE_DIR})

# Optionally, specify any additional compiler options or flags
# target_compile_options(project PRIVATE ...)

# Optionally, add any other dependencies or configurations needed for your project
