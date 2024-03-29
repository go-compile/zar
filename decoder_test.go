package zar

import (
	"bytes"
	"testing"
)

var testArchiveKey = []byte("password123")

func TestDecodeBlock(t *testing.T) {
	archive, err := encodeArchive()
	if err != nil {
		t.Fatal(err)
	}
	r := bytes.NewReader(archive)

	d, err := NewDecoder(r, testArchiveKey, int64(len(archive)))
	if err != nil {
		t.Fatal(err)
	}

	err = d.Extract("./testdata/extract")
	if err != nil {
		t.Fatal(err)
	}
	// fmt.Println(d.decryptBlocks(1, 10, d.iv, os.Stdout))

}

func encodeArchive() ([]byte, error) {
	output := bytes.NewBuffer(nil)
	archive, err := New(output, testArchiveKey)
	if err != nil {
		return nil, err
	}

	buf := bytes.NewBuffer([]byte("my file contents..."))
	_, err = archive.Add("test.txt", 0, buf)
	if err != nil {
		return nil, err
	}

	buf2 := bytes.NewBuffer([]byte("another file"))
	_, err = archive.Add("test2.txt", 0, buf2)
	if err != nil {
		return nil, err
	}

	buf3 := bytes.NewBuffer([]byte("mid 18th Century"))
	_, err = archive.Add("some/file.txt", 0, buf3)
	if err != nil {
		return nil, err
	}

	if err := archive.Close(); err != nil {
		return nil, err
	}

	return output.Bytes(), nil
}
