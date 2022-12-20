package zar_test

import (
	"bytes"
	"testing"

	"github.com/andybalholm/brotli"
)

func TestBrotil(t *testing.T) {
	msg := []byte("Message test 1")

	buf := bytes.NewBuffer(nil)
	w := brotli.NewWriter(buf)

	_, err := w.Write(msg)
	if err != nil {
		t.Fatal(err)
	}

	w.Close()

	output := make([]byte, 200)
	n, err := brotli.NewReader(buf).Read(output)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(output[:n], msg) {
		t.Fatal("input did not match output")
	}
}

func TestBrotilCustomLevels(t *testing.T) {
	msg := []byte("Message test 2")

	buf := bytes.NewBuffer(nil)
	w := brotli.NewWriterLevel(buf, brotli.BestCompression)

	_, err := w.Write(msg)
	if err != nil {
		t.Fatal(err)
	}

	w.Close()

	output := make([]byte, 200)
	n, err := brotli.NewReader(buf).Read(output)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(output[:n], msg) {
		t.Fatal("input did not match output")
	}
}
