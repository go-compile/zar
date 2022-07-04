package zar

import (
	"path/filepath"
	"strings"
)

func validateName(path string) bool {
	// Deny absolute paths
	// Deny path traversal
	// Allow filenames to contains ".." but not exclusively
	// Deny invalid characters
	if strings.ContainsAny(path, "<>?:*|") {
		return false
	}

	path = filepath.Clean(path)

	if len(path) < 1 {
		return false
	}

	// Path must not be absolute
	if path[0] == '\\' || path[0] == '/' {
		return false
	}

	// Disallow traversing up a directory with ".." and prevent relative dir "."
	if path[0] == '.' {
		if len(path) > 2 {
			// check if path is "../"
			if path[1] == '.' && (path[2] == '/' || path[2] == '\\') {
				return false
			}
		} else if len(path) > 1 {
			// check if path is ".."
			return !(path[1] == '.')
		}

		// file name just starts with a dot
	}

	return true
}
