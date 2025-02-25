# Get all dependencies for ${lib} and add them to ${LIBDIRS_VAR} and ${LIBS_VAR}. Ignore any
# dependencies in the list ${ignored} to: - avoid infinite recursion - avoid libscap dependencies in
# libsinsp.pc (which requires libscap.pc and pulls them in that way)
function(add_pkgconfig_library LIBDIRS_VAR LIBS_VAR lib ignored)

	message(DEBUG "[add_pkgconfig_library] processing lib \"${lib}\"")
	# if it's not a target, it doesn't have dependencies we know or care about
	if(NOT TARGET ${lib})
		return()
	endif()

	# get the libraries that ${lib} links to
	get_target_property(PKGCONFIG_LIBRARIES ${lib} LINK_LIBRARIES)
	if("${PKGCONFIG_LIBRARIES}" STREQUAL "PKGCONFIG_LIBRARIES-NOTFOUND")
		return()
	endif()

	message(DEBUG "[add_pkgconfig_library] LINK_LIBRARIES property: \"${PKGCONFIG_LIBRARIES}\"")

	get_property(
		target_type
		TARGET ${lib}
		PROPERTY TYPE
	)
	message(DEBUG "[add_pkgconfig_library] ignored list: \"${ignored}\"")
	foreach(dep ${PKGCONFIG_LIBRARIES})
		# XXX: We use a (very) loose match as we are potentially comparing absolute library file
		# names (dep) to pkg-config library names to be ignored.  The only alternative I can think
		# of would be to maintain a map associating pkg-config names to their library file name.
		get_filename_component(dep_base ${dep} NAME_WE)
		string(REGEX REPLACE "^lib" "" dep_name ${dep_base})
		# For CMake imported targets, keep only the suffix, e.g. gRPC::grpc -> grpc.
		string(REGEX REPLACE "[^:]*::" "" dep_name ${dep_base})
		message(DEBUG "[add_pkgconfig_library] processing dep ${dep}")
		string(FIND "${ignored}" "${dep_name}" find_result)
		if(NOT ${find_result} EQUAL -1)
			message(DEBUG "[add_pkgconfig_library] \"${dep}\" ignored")
			continue()
		endif()

		if(${target_type} STREQUAL "SHARED_LIBRARY")
			# for shared libraries, do not add static libraries as dependencies
			if(TARGET ${dep})
				# skip static libraries which are CMake targets
				get_property(
					dep_target_type
					TARGET ${dep}
					PROPERTY TYPE
				)
				if(NOT ${dep_target_type} STREQUAL "SHARED_LIBRARY")
					continue()
				endif()
			else()
				# skip static libraries which are just file paths
				get_filename_component(ext ${dep} LAST_EXT)
				if("${ext}" STREQUAL "${CMAKE_STATIC_LIBRARY_SUFFIX}")
					continue()
				endif()
			endif()
		elseif(${target_type} STREQUAL "STATIC_LIBRARY")
			# for static libraries which are not CMake targets, redirect them to
			# ${libdir}/${LIBS_PACKAGE_NAME} note that ${libdir} is not a CMake variable, but a
			# pkgconfig variable, so we quote it and end up with a literal ${libdir} in the
			# pkgconfig file
			if(NOT TARGET ${dep})
				get_filename_component(filename ${dep} NAME)
				set(dep "\${libdir}/${LIBS_PACKAGE_NAME}/${filename}")
			else()
				get_property(
					dep_target_type
					TARGET ${dep}
					PROPERTY TYPE
				)
				if(${dep_target_type} STREQUAL "OBJECT_LIBRARY")
					# skip object libraries
					continue()
				endif()

				# if the library is imported, use the IMPORTED_LOCATION instead
				get_property(
					dep_imported_location
					TARGET ${dep}
					PROPERTY IMPORTED_LOCATION
				)
				if(NOT ${dep_imported_location} STREQUAL "")
					get_filename_component(filename ${dep_imported_location} NAME)
					set(dep "\${libdir}/${LIBS_PACKAGE_NAME}/${filename}")
				endif()
			endif()
		endif()

		add_pkgconfig_dependency(${LIBDIRS_VAR} ${LIBS_VAR} ${dep} "${ignored}")
	endforeach()

	# Remove duplicate search paths. We cannot remove duplicates from ${LIBS_VAR} because the order
	# of libraries is important.
	list(REMOVE_DUPLICATES ${LIBDIRS_VAR})

	set(${LIBS_VAR}
		${${LIBS_VAR}}
		PARENT_SCOPE
	)
	set(${LIBDIRS_VAR}
		${${LIBDIRS_VAR}}
		PARENT_SCOPE
	)
endfunction()

function(add_pkgconfig_dependency LIBDIRS_VAR LIBS_VAR lib ignored)
	if(${lib} IN_LIST ignored)
		# already processed, avoid infinite recursion
	elseif(${lib} MATCHES "^-")
		# We have a flag. Pass it through unchanged.
		list(APPEND ${LIBS_VAR} ${lib})
	elseif(${lib} MATCHES "/")
		# We have a path. Convert it to -L<dir> + -l<lib>.
		get_filename_component(lib_dir ${lib} DIRECTORY)
		list(APPEND ${LIBDIRS_VAR} -L${lib_dir})
		get_filename_component(lib_base ${lib} NAME_WE)
		string(REGEX REPLACE "^lib" "" lib_base ${lib_base})
		list(APPEND ${LIBS_VAR} -l${lib_base})
	else()
		# Assume we have a plain library name. Prefix it with "-l". Then recurse into its
		# dependencies but ignore the library itself, so we don't end up in an infinite loop with
		# cyclic dependencies
		list(APPEND ${LIBS_VAR} -l${lib})
		list(APPEND ignored ${lib})
		add_pkgconfig_library(${LIBDIRS_VAR} ${LIBS_VAR} ${lib} "${ignored}")
	endif()
	set(${LIBS_VAR}
		${${LIBS_VAR}}
		PARENT_SCOPE
	)
	set(${LIBDIRS_VAR}
		${${LIBDIRS_VAR}}
		PARENT_SCOPE
	)
endfunction()
