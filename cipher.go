package zar

import (
	"crypto/cipher"
	"hash"
	"io"
)

type streamCipher struct {
	src    io.Reader
	dst    io.Writer
	stream cipher.Stream
	mac    hash.Hash
	size   uint64
}

func newCipher(mac hash.Hash, r io.Reader, w io.Writer, stream cipher.Stream) streamCipher {

	return streamCipher{
		src:    r,
		dst:    w,
		mac:    mac,
		stream: stream,
	}
}

// MAC returns the message authentication code
func (c *streamCipher) MAC() []byte {
	return c.mac.Sum(nil)
}

func (c *streamCipher) Read(p []byte) (int, error) {
	n, err := c.src.Read(p)
	if n == 0 || err == io.EOF {
		return 0, io.EOF
	} else if err != nil {
		return n, err
	}

	c.size += uint64(n)

	// encrypt input and write mac using cipher text (Encrypt then Mac, EtM)
	c.stream.XORKeyStream(p[:n], p[:n])
	_, err = c.mac.Write(p[:n])
	if err != nil {
		return 0, err
	}

	return n, nil
}

func (c *streamCipher) Write(p []byte) (int, error) {
	// encrypt input and write mac using cipher text (Encrypt then Mac, EtM)
	c.stream.XORKeyStream(p, p)
	_, err := c.mac.Write(p)
	if err != nil {
		return 0, err
	}
	c.size += uint64(len(p))

	return c.dst.Write(p)
}
