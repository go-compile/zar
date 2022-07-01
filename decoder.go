package zar

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"

	"github.com/andybalholm/brotli"
	"github.com/dchest/siphash"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

var (
	// ErrShotRead is returned when read didn't fill buffer
	ErrShotRead = errors.New("short read")
)

// Decoder will take a reader of the archive file
type Decoder struct {
	r   io.ReaderAt
	key []byte

	// masterMac is used with AES_256_CTR as a EtM MAC
	masterMac hash.Hash
	// mac is SipHash for each compression block
	mac        hash.Hash
	size       int64
	bodyOffset int64

	block           cipher.Block
	cipherBlockSize int64
	salt            []byte
	compression     int
}

// NewDecoder creates a new zar archive decoder
func NewDecoder(r io.ReaderAt, key []byte, size int64) (*Decoder, error) {

	return &Decoder{
		r:               r,
		key:             key,
		masterMac:       sha512.New(),
		size:            size,
		cipherBlockSize: aes.BlockSize,
		compression:     brotli.DefaultCompression,
	}, nil
}

func (d *Decoder) Extract(output string) error {
	r := d.r

	if err := d.prepareDecoder(r); err != nil {
		return err
	}

	ivBuf := make([]byte, d.cipherBlockSize)
	almanac, err := getAlmanac(d, ivBuf)
	if err != nil {
		return err
	}

	fmt.Println(almanac)

	return nil
}

// prepareDecoder will setup the decoder with the appropriate ciphers, IVs, keys etc
func (d *Decoder) prepareDecoder(r io.ReaderAt) error {
	salt := make([]byte, aes.BlockSize)

	if _, err := readAtFull(r, salt, 0); err != nil {
		return err
	}

	d.salt = salt

	d.bodyOffset = int64(len(salt) + len(d.salt))

	// Run the key through Argon2Key KDF
	k1 := argon2.Key(d.key, salt, 1, 20, 1, 32)

	// derive additional keys from master
	kdf := hkdf.New(sha512.New, k1, nil, nil)

	// k2 is used for the master mac
	k2 := make([]byte, 32)
	// k3 is used for SipHash
	k3 := make([]byte, 32)
	// k4 is used for encryption
	k4 := make([]byte, 32)

	if _, err := io.ReadFull(kdf, k2); err != nil {
		return err
	}

	if _, err := io.ReadFull(kdf, k3); err != nil {
		return err
	}

	if _, err := io.ReadFull(kdf, k4); err != nil {
		return err
	}

	block, err := aes.NewCipher(k4)
	if err != nil {
		return err
	}

	d.block = block
	d.mac = siphash.New(k3)

	return nil
}

func (d *Decoder) almanacOffset(ivBuf []byte, lastBlock int64) (uint64, error) {
	// decrypt last 2 ciphertext blocks
	lastBlocks := bytes.NewBuffer(nil)
	if err := d.decryptBlocks(lastBlock-2, lastBlock, ivBuf, lastBlocks); err != nil {
		return 0, err
	}

	almanacOffset := pkcs5Unmarshal(lastBlocks.Bytes())
	almanacOffset = almanacOffset[len(almanacOffset)-8:]

	return binary.BigEndian.Uint64(almanacOffset), nil
}

func readAtFull(r io.ReaderAt, p []byte, offset int64) (int, error) {
	n, err := r.ReadAt(p, offset)
	if err != nil {
		return n, err
	}

	if n != len(p) {
		return n, ErrShotRead
	}

	return n, nil
}

func (d *Decoder) decryptBlocks(start, finish int64, ivBuf []byte, w io.Writer) error {

	// initialise IV
	counter := big.NewInt(0).SetBytes(d.salt)
	// increment counter to block
	counter.Add(counter, big.NewInt(start)).FillBytes(ivBuf)

	c := cipher.NewCTR(d.block, ivBuf)

	p := make([]byte, d.cipherBlockSize)
	for i := start; i < finish; i++ {
		n, err := d.r.ReadAt(p, d.bodyOffset+(i*d.cipherBlockSize))
		if err != nil {
			return err
		}

		// encrypt input and write mac using cipher text (Encrypt then Mac, EtM)
		c.XORKeyStream(p[:n], p[:n])
		_, err = d.masterMac.Write(p[:n])
		if err != nil {
			return err
		}

		if _, err := w.Write(p[:n]); err != nil {
			return err
		}
	}

	return nil
}

func getAlmanac(d *Decoder, ivBuf []byte) (*Almanac, error) {
	lastBlock := (d.size - d.bodyOffset - 64) / d.cipherBlockSize

	almanacOffset, err := d.almanacOffset(ivBuf, lastBlock)
	if err != nil {
		return nil, err
	}

	// Calculate the block ID
	row := (almanacOffset / 16) + 1

	almanacBuf := bytes.NewBuffer(nil)
	if err := d.decryptBlocks(int64(row)-1, lastBlock, ivBuf, almanacBuf); err != nil {
		return nil, err
	}

	// remove padding and almanac offset
	almanacBuf.Truncate(len(pkcs5Unmarshal(almanacBuf.Bytes())) - 8)

	almanac, err := d.unmarshalAlmanac(almanacBuf, int64(((row*16)+almanacOffset)%16))
	if err != nil {
		return nil, err
	}

	return almanac, nil
}
