set(FNOX_RECOMMENDED_NODE_VERSION "26.13.0")

function(fnox_require_typescript_node version_output executable)
  if(NOT "${version_output}" MATCHES "^v?([0-9]+)\\.([0-9]+)\\.([0-9]+)")
    message(FATAL_ERROR "Could not determine the Node.js version from ${executable}")
  endif()

  set(node_major "${CMAKE_MATCH_1}")
  set(node_minor "${CMAKE_MATCH_2}")
  if(node_major EQUAL 23 AND node_minor LESS 6)
    message(FATAL_ERROR "Requires Node.js 23.6+; found ${version_output}. Node.js ${FNOX_RECOMMENDED_NODE_VERSION} LTS recommended.")
  elseif(node_major LESS 22 OR
         (node_major EQUAL 22 AND node_minor LESS 18))
    message(FATAL_ERROR "Requires Node.js 22.18+; found ${version_output}. Node.js ${FNOX_RECOMMENDED_NODE_VERSION} LTS recommended.")
  endif()
endfunction()
