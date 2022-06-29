package zar

// BlockMacSize is the size of the message authentication code for a block
const BlockMacSize = 8

// Block is a collection of files, or one large file, combined into
// one buffer which is compressed together and authenticated with SipHash.
//
// This block represents a NON compressed buffer i.e. decompression has already
// been executed.
type Block []byte

// MAC returns the MAC for the block.
//
// If len(block) < 8 the method will panic
func (b Block) MAC() []byte {
	return b[len(b)-BlockMacSize:]
}
