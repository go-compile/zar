package zar

import (
	"encoding/binary"
	"errors"
	"io"

	"github.com/andybalholm/brotli"
)

var (
	// ErrIntegrityFailed is returned when a computed and actual MAC does not
	// match
	ErrIntegrityFailed = errors.New("integrity check failed")
)

func (d *Decoder) unmarshalAlmanac(r io.Reader, offset int64) (*Almanac, error) {
	// read n bytes from buffer which are in this crypto block but not in the
	// compression block
	discard := make([]byte, offset)
	if _, err := r.Read(discard); err != nil {
		return nil, err
	}

	// read SipHash
	// if _, err := io.ReadFull(r, buf); err != nil {
	// 	return nil, err
	// }

	// if !bytes.Equal(h.Sum(nil), buf) {
	// 	return nil, ErrIntegrityFailed
	// }

	// h.Reset()

	return decodeAlmanac(brotli.NewReader(r))
}

func decodeAlmanac(r io.Reader) (*Almanac, error) {

	buf := make([]byte, 8)

	// read file count
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}

	fileCount := binary.BigEndian.Uint64(buf)
	almanac := &Almanac{
		Files: make([]File, fileCount),
	}

	// preallocate buffers
	block := make([]byte, 8)
	modified := make([]byte, 8)
	size := make([]byte, 8)
	nameLen := make([]byte, 2)

	for i := uint64(0); i < fileCount; i++ {
		if _, err := io.ReadFull(r, block); err != nil {
			return nil, err
		}

		if _, err := io.ReadFull(r, size); err != nil {
			return nil, err
		}

		if _, err := io.ReadFull(r, modified); err != nil {
			return nil, err
		}

		if _, err := io.ReadFull(r, nameLen); err != nil {
			return nil, err
		}

		name := make([]byte, binary.BigEndian.Uint16(nameLen))
		if _, err := io.ReadFull(r, name); err != nil {
			return nil, err
		}

		f := File{
			Block:    binary.BigEndian.Uint64(block),
			Size:     binary.BigEndian.Uint64(size),
			Modified: binary.BigEndian.Uint64(modified),
			Name:     string(name),
		}

		almanac.Files[i] = f
	}

	// read note, reuse nameLen buffer
	if _, err := io.ReadFull(r, nameLen); err != nil {
		return nil, err
	}

	note := make([]byte, binary.BigEndian.Uint16(nameLen))
	if _, err := io.ReadFull(r, note); err != nil {
		return nil, err
	}

	almanac.Note = note

	return almanac, nil

}
