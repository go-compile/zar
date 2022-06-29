package zar

import (
	"bytes"
	"testing"
)

func TestPKCS5(t *testing.T) {
	plain := []byte("This is my message")
	blockSize := 16

	padded := pkcs5(len(plain), blockSize)
	output := append(plain, padded...)

	if x := len(output) % blockSize; x != 0 {
		t.Fatalf("expected output len to be a factor of %d instead len MOD blockSize = %d", blockSize, x)
	}

	if !bytes.Equal(plain, pkcs5Unmarshal(output)) {
		t.Fatal("could not decode PKCS5 padding")
	}
}

func FuzzPKCS5(f *testing.F) {
	f.Add(16, "This is a message")
	f.Add(16, "Here is another")
	f.Add(12, "Here is another")
	f.Add(16, "Random seeds 92379")
	f.Add(16, "More random 39u0asjd0ajs0dja0s9dh0")
	f.Add(16, "We could make this very random aoshdfoioahsdoifh and very long")
	f.Add(32, "We could make this very random aoshdfoioahsdoifh and very long")
	f.Add(12, "We could make this very random aoshdfoioahsdoifh and very long")
	f.Add(6, "We could make this very random aoshdfoioahsdoifh and very long")
	f.Add(8, "We could make this very random aoshdfoioahsdoifh and very long")
	f.Add(8, "\xb1h\xb3\xbf\xbf\xb9")

	f.Fuzz(func(t *testing.T, blockSize int, plain string) {
		// ignore negative blocksizes and ones above max
		if blockSize < 1 || blockSize > 255 {
			return
		}

		padded := pkcs5(len(plain), blockSize)
		output := append([]byte(plain), padded...)

		if x := len(output) % blockSize; x != 0 {
			t.Fatalf("expected output len to be a factor of %d instead len MOD blockSize = %d", blockSize, x)
		}

		if !bytes.Equal([]byte(plain), pkcs5Unmarshal(output)) {
			t.Fatal("could not decode PKCS5 padding")
		}
	})
}
