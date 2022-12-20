package zar

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"hash"
	"io"

	"github.com/andybalholm/brotli"
	"github.com/dchest/siphash"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

// Encoder writes the archive
type Encoder struct {
	w io.Writer

	// k1 is the key used for encryption and HMACs
	k1, k2, k3 []byte
	// salt is used in the key KDF
	salt    []byte
	almanac []File

	stream *streamCipher

	brotilW *brotli.Writer
	// fileMac is used to hash the individual files in the repo
	fileMac hash.Hash

	compressionLevel int
	note             []byte
	cipherBlockSize  uint64
}

// New creates a new ZAR encoder
func New(w io.Writer, key []byte) (*Encoder, error) {
	// TODO: write header
	// TODO: accept options; KDF, MAC, HKDF CHF

	// generate salt/IV for KDF and AES
	salt := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	// write salt to file
	if _, err := w.Write(salt); err != nil {
		return nil, err
	}

	// Run the key through Argon2Key KDF
	k1 := argon2.Key(key, salt, 1, 20, 1, 32)

	// derive additional keys from master
	kdf := hkdf.New(sha512.New, k1, nil, nil)

	// k2 is used for the master mac
	k2 := make([]byte, 32)
	// k3 is used for SipHash
	k3 := make([]byte, 32)
	// k4 is used for encryption
	k4 := make([]byte, 32)

	if _, err := io.ReadFull(kdf, k2); err != nil {
		return nil, err
	}

	if _, err := io.ReadFull(kdf, k3); err != nil {
		return nil, err
	}

	if _, err := io.ReadFull(kdf, k4); err != nil {
		return nil, err
	}

	masterMac := hmac.New(sha512.New, k2)

	// Create new AES_256 cipher
	block, err := aes.NewCipher(k4)
	if err != nil {
		return nil, err
	}

	if _, err := w.Write(salt); err != nil {
		return nil, err
	}

	// Set mode to CTR
	c := cipher.NewCTR(block, salt)

	// stream output to file
	stream := newCipher(masterMac, nil, w, c)

	return &Encoder{
		w:  w,
		k1: k1,
		k2: k2,
		k3: k3,

		stream:           &stream,
		salt:             salt,
		compressionLevel: brotli.DefaultCompression,

		brotilW: brotli.NewWriterLevel(&stream, brotli.DefaultCompression),
		fileMac: siphash.New(k3),

		cipherBlockSize: uint64(block.BlockSize()),
	}, nil
}

// Close must be called to finalise the archive
func (e *Encoder) Close() error {
	// e.closeBlock()
	return e.writeAlmanac()
}

func (e *Encoder) writeAlmanac() error {
	almanacOffset := e.stream.size
	w := brotli.NewWriterLevel(e.stream, e.compressionLevel)

	// write array size of almanac
	fileCount := make([]byte, 8)
	binary.BigEndian.PutUint64(fileCount, uint64(len(e.almanac)))
	if _, err := w.Write(fileCount); err != nil {
		return err
	}

	e.fileMac.Write(fileCount)

	buf := make([]byte, 8)
	for i := 0; i < len(e.almanac); i++ {
		// write block offset
		binary.BigEndian.PutUint64(buf, e.almanac[i].Offset)
		if _, err := w.Write(buf); err != nil {
			return err
		}

		// compute message authentication code
		e.fileMac.Write(buf)

		// write file size
		binary.BigEndian.PutUint64(buf, e.almanac[i].Size)
		if _, err := w.Write(buf); err != nil {
			return err
		}

		// compute message authentication code
		e.fileMac.Write(buf)

		// write modified date
		binary.BigEndian.PutUint64(buf, e.almanac[i].Modified)
		if _, err := w.Write(buf); err != nil {
			return err
		}

		// compute message authentication code
		e.fileMac.Write(buf)

		// write file name length
		binary.BigEndian.PutUint16(buf, uint16(len(e.almanac[i].Name)))
		if _, err := w.Write(buf[:2]); err != nil {
			return err
		}

		// compute message authentication code
		e.fileMac.Write(buf[:2])

		// write file name
		if _, err := w.Write([]byte(e.almanac[i].Name)); err != nil {
			return err
		}

		// compute message authentication code
		e.fileMac.Write([]byte(e.almanac[i].Name))
	}

	// write note length
	binary.BigEndian.PutUint16(buf, uint16(len(e.note)))
	if _, err := w.Write(buf[:2]); err != nil {
		return err
	}

	// compute message authentication code
	e.fileMac.Write(buf[:2])

	// write note
	if _, err := w.Write(e.note); err != nil {
		return err
	}

	// compute message authentication code
	e.fileMac.Write(e.note)

	// write almanac mac
	if _, err := w.Write([]byte(e.fileMac.Sum(nil))); err != nil {
		return err
	}

	e.fileMac.Reset()

	// finalise compression
	if err := w.Close(); err != nil {
		return err
	}

	// write almanac offset
	binary.BigEndian.PutUint64(buf, almanacOffset)
	if _, err := e.stream.Write(buf); err != nil {
		return err
	}

	// pad ciphertext
	padding := pkcs5(e.stream.size, e.cipherBlockSize)
	if _, err := e.stream.Write(padding); err != nil {
		return err
	}

	// append EtM master Mac
	if _, err := e.w.Write(e.stream.MAC()); err != nil {
		return err
	}

	return nil
}

// Add will read a file and add it to the archive
func (e *Encoder) Add(name string, modified uint64, r io.Reader) (int64, error) {

	// will be used to calculate the size of the Brotil output
	sizeBefore := e.stream.size
	fmt.Printf("BEFORE === %-16s %s: %d\n", "Stream Size", name, sizeBefore)

	// create new brotil compressor which directs output into AES_256_CTR
	// stream
	brotilW := brotli.NewWriterLevel(e.stream, e.compressionLevel)

	// stream file -> compressor -> AES -> output file
	//             -> SipHash
	n, err := io.Copy(io.MultiWriter(brotilW, e.fileMac), r)
	if err != nil {
		return n, err
	}

	mac := e.fileMac.Sum(nil)
	fmt.Printf("MAC %X\n", mac)

	// Sum MAC and compress it with block
	brotilW.Write(mac)
	e.fileMac.Reset()

	if err := brotilW.Close(); err != nil {
		return 0, err
	}

	e.almanac = append(e.almanac, File{
		Name:     name,
		Modified: modified,
		Size:     e.stream.size - sizeBefore,
		Offset:   sizeBefore, //TODO: calculate bytes from block start
	})

	fmt.Printf("AFTER  === %-16s %s: %d\n", "Stream Size", name, e.stream.size)
	fmt.Printf("AFTER  === %-16s %s: %d\n", "Offset", name, e.stream.size-sizeBefore)

	return n, nil
}
