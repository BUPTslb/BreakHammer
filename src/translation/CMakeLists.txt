add_library(ramulator-translation OBJECT)

# Bind the loaded shared library to the exact stable-translation source.  The
# adapter compares this embedded digest with the checked-out file before a
# matched deployment can be certified.
set(STABLE_PER_CORE_TRANSLATION_SOURCE
    "${CMAKE_CURRENT_SOURCE_DIR}/impl/stable_per_core_translation.cpp")
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
             "${STABLE_PER_CORE_TRANSLATION_SOURCE}")
file(SHA256 "${STABLE_PER_CORE_TRANSLATION_SOURCE}"
     STABLE_PER_CORE_TRANSLATION_SOURCE_SHA256)
target_compile_definitions(
  ramulator-translation PRIVATE
  STABLE_PER_CORE_TRANSLATION_SOURCE_SHA256="${STABLE_PER_CORE_TRANSLATION_SOURCE_SHA256}"
)

target_sources(
  ramulator-translation PRIVATE
  translation.h

  impl/no_translation.cpp
  impl/random_translation.cpp
  "${STABLE_PER_CORE_TRANSLATION_SOURCE}"
)

target_link_libraries(
  ramulator
  PRIVATE
  ramulator-translation
)
