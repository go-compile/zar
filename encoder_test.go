package zar_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/go-compile/zar"
)

func TestEncode(t *testing.T) {

	output := bytes.NewBuffer(nil)
	archive, err := zar.New(output, []byte("password123"))
	if err != nil {
		t.Fatal(err)
	}

	buf := bytes.NewBuffer([]byte("my file contents..."))
	n, err := archive.Add("/test.txt", 0, buf)
	if err != nil {
		fmt.Println(n, err)
	}

	fmt.Println(n)
	buf.Write([]byte("oasasjdoasidjdojasoidfoisjdfoi"))
	n, err = archive.Add("/asoidjfoiasjdfoi.txt", 0, buf)
	if err != nil {
		fmt.Println(n, err)
	}

	archive.Close()

	fmt.Printf("%X\n", output)
}
