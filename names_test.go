package zar

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateFileName(t *testing.T) {
	pathSucceed(t, "0")
	pathSucceed(t, "00")
	pathSucceed(t, "aaa")
	pathSucceed(t, "...")
	pathSucceed(t, "FILE.TXT")
	pathSucceed(t, ".txt")
	pathSucceed(t, "..txt")
	pathSucceed(t, ".../txt")
}

func FuzzFileName(f *testing.F) {
	f.Add("not-a-absolute/path")
	f.Add("also/not/a/absolute/path.txt")
	f.Add("absolute/../home.txt")
	f.Add("file/../")
	f.Add("normal/path/going/../somewhere/groceries.txt")
	f.Add("name/path/../../")

	f.Fuzz(func(t *testing.T, path string) {
		t.Parallel()

		if !validateName(path) {
			t.Fail()
		}
	})
}

func FuzzFileNameAbsolute(f *testing.F) {
	f.Add("absolute/path")
	f.Add("absolute/path.txt")
	f.Add("absolute/../home.txt")
	f.Add("../")
	f.Add("file/../")
	f.Add("file/../../")
	f.Add("file../")
	f.Add("file../../")
	f.Add("name/path/../something/../../")

	f.Fuzz(func(t *testing.T, path string) {
		t.Parallel()

		if validateName(`\` + path) {
			t.Fail()
		}

		if validateName(`/` + path) {
			t.Fail()
		}
	})
}

// FuzzFileNameFail should only use the provided inputs
func FuzzFileNameFail(f *testing.F) {
	f.Add("../")
	f.Add("name/../../")
	f.Add("name/path/../something/../../x/../../")

	f.Fuzz(func(t *testing.T, path string) {
		t.Parallel()

		if validateName(path) {
			t.Fail()
		}
	})
}

func FuzzFileNamePathTraversal(f *testing.F) {
	f.Add("../")
	f.Add("file/../")
	f.Add("name/../../")
	f.Add("name/path/../../")
	f.Add("name/path/../something/../../")
	f.Add("file../../")
	f.Add("0")
	f.Add("/")

	cwd := "/home/ubuntu/go/src/zar"
	f.Fuzz(func(t *testing.T, path string) {
		t.Parallel()

		// if path traverses and validate returns true fail
		if pathTraverses(cwd, path) || nameFailCase(path) {
			if validateName(path) {
				t.Fail()
				t.Log("\"VALID\":", path)
				t.Log(filepath.Join(cwd, path))
			}
		} else {
			if !validateName(path) {
				t.Log(`"INVALID"`, path)
				t.Log(filepath.Join(cwd, path))
				t.Fail()
			}
		}
	})
}

func pathTraverses(parent, path string) bool {
	clean := filepath.Join(parent, path)
	if len(clean) < len(parent) {
		return true
	}

	// replace windows path separators with unix ones
	// to compare with unix based path used above
	clean = strings.Replace(clean, "\\", "/", -1)
	return clean[:len(parent)] != parent
}

func nameFailCase(path string) bool {
	if strings.ContainsAny(path, "<>?:*|") {
		return true
	}

	switch path {
	case "/", "\\":
		return true
	default:
		if strings.HasPrefix(path, "/") {
			return true
		}

		if strings.HasPrefix(path, "\\") {
			return true
		}

		return false
	}
}

func pathSucceed(t *testing.T, path string) {
	if !validateName(path) {
		t.Fail()
	}
}
