package zar

import (
	"crypto/aes"
)

// Header is the first 7 bytes of a file and contains metadata
// on how to open it
type Header struct {
	MagicNumber [3]byte
	Mode        uint8
	CipherSuite uint8
	Mac         uint8
	Compression uint8
}

// Index stores the metadata for each file and acts as the almanac
type Index struct {
	// Files is a list of meta data pointing to the location of each file
	Files []File
	// MAC is SipHash used to authenticate this section has not
	// been modified without having to authenticate the full archive
	MAC []byte
}

// File holds metadata on a file and the parameters used to locate it
type File struct {
	// Name refers to the relative path name without the "/" prefix
	Name string
	// Modified is the file modified date
	Modified uint64
	// Size refers to the size of the file in bytes
	Size uint64
	// Block is a offset from the start of the encrypted body
	Block uint64
}

// Start returns the relative offset within the block to the start of
// the file.
func (f *File) Start(index []File, id int) uint64 {
	// if we are fetching the first file the start offset
	// will always be zero
	if id == 0 {
		return 0
	}

	offset := uint64(0)

	// regress until we find a match
	for i := id - 1; i >= 0; i-- {
		// if we find a different block break and return offset
		if index[i].Block != f.Block {
			return offset
		}

		// Sum size of files within same block
		offset += index[i].Size
	}

	return offset
}

// End returns the relative end index of the file
func (f *File) End(start uint64) uint64 {
	return f.Size + start
}

// CipherBlock returns the ciphertext block ID of the compression
// block
func (f *File) CipherBlock() uint64 {
	x := f.Block % aes.BlockSize
	return (f.Block - x) / aes.BlockSize
}

// CipherBlockOffset returns the distance between the start of the cipher's block
// and the compression block's start
func (f *File) CipherBlockOffset() uint64 {
	cipherBlock := f.CipherBlock()
	return f.Block - (cipherBlock * aes.BlockSize)
}

// BlockSize returns the compressed length of the block
func (f *File) BlockSize(index []File, id int) uint64 {

	// sum the sizes for all files within the same block
	for i := id + 1; i < len(index); i++ {
		if offset := index[i].Block; offset != f.Block {
			return offset - f.Start(index, id)
		}
	}

	return f.Size
}
