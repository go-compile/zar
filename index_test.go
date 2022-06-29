package zar_test

import (
	"fmt"
	"math/rand"
	"testing"

	"github.com/go-compile/zar"
)

const compressionBlockSize = 300

func TestIndexStart(t *testing.T) {
	_, files := generateFile(10)
	for i, f := range files {
		fmt.Printf("%d: Block: %d Len %d Start: %d CryptoBlock: %d Relative Crypto Block Offset: %d\n", i, f.Block, f.Size, f.Start(files, i), f.CipherBlock(), f.CipherBlockOffset())
	}
}

func generateFile(amount int) (files [][]byte, indexes []zar.File) {
	blockSize := 0
	blockOffset := uint64(0)

	for i := 1; i <= amount; i++ {
		if blockSize >= compressionBlockSize {
			blockOffset += uint64(blockSize)
			blockSize = 0
		}

		data := make([]byte, rand.Int31n(300))
		file := zar.File{
			Name:     "home",
			Modified: 0,
			Size:     uint64(len(data)),
			Block:    blockOffset,
		}

		blockSize += len(data)

		files = append(files, data)
		indexes = append(indexes, file)
	}

	return files, indexes
}
