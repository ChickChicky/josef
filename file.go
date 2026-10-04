package josef

// afero.File implementation for Josef

// TODO: Use https://github.com/go-faster/xor for XOR operations
// TODO: Optimize reads/writes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/afero"
)

const SaltSize = 8

const badOffset = 0xffffffffffffffff

type fileState struct {
	// size of the file
	size uint64
	// current offset
	off uint64
	// current file offset
	foff uint64
}

type File struct {
	log *slog.Logger
	key [KeySize]byte
	path string
	base afero.File

	cipher cipher.Block
	
	salt [SaltSize]byte
	s *fileState
}

// initializes the file's state
func (f *File) init(new bool) error {
	var err error
	if new {
		f.s.size = 0
		rand.Read(f.salt[:])
		err = f.storeMeta()
		if err != nil { return err }
		err = f.base.Truncate(BlockSize)
	} else {
		err = f.loadMeta()
	}
	if err != nil {return err }
	f.s.off = 0
	return nil
}

// Gets the mask for a block in the file
func (f *File) blockMask(dst *[BlockSize]byte, idx uint64) {
	binary.BigEndian.PutUint64(dst[:], idx)
	for i := range ceildiv(BlockSize, 8) {
		copy(dst[i*8+8:], dst[i*8:i*8+8])
	}
	if idx != 0 {
		// for i := range ceildiv(blockSize, saltSize) {
		// 	for j := range saltSize {
		// 		dst[i*saltSize+j] ^= f.salt[j]
		// 	}
		// }
		for i := range BlockSize {
			dst[i] ^= f.salt[i%SaltSize]
		}
	}
	f.cipher.Encrypt(dst[:], dst[:])
}

// Loads the meta block of the file (first one)
func (f *File) loadMeta() error {
	var meta [BlockSize]byte
	err := f.readBlockAt(&meta, 0)
	if err != nil {
		return err
	}
	f.s.size = binary.BigEndian.Uint64(meta[:])
	copy(f.salt[:], meta[8:])
	return nil
}

// Saves the meta block to the file (first one)
func (f *File) storeMeta() error {
	var meta [BlockSize]byte
	binary.BigEndian.PutUint64(meta[:], f.s.size)
	copy(meta[8:], f.salt[:])
	return f.writeBlockAt(&meta, 0)
}

// Begins a read/write sequence at the specified offset in the file
// The offset must be at the start of a block
func (f *File) beginSeqAt(at uint64) error {
	if at%BlockSize != 0 {
		return JosefError{m: "Bad offset"}
	}
	off, err := f.base.Seek(int64(at), 0)
	if err != nil {
		return err
	}
	if off < 0 || uint64(off) != at {
		f.s.foff = badOffset
		return JosefError{m: "Failed to seek"}
	}
	f.s.foff = at
	return nil
}

func (f *File) readBlockAt(dst *[BlockSize]byte, idx uint64) error {
	var n int
	var err error

	// Tries sequential Read(), or defaults to ReadAt()
	if f.s.foff == idx*BlockSize {
		// fmt.Printf("  r\x1b[92mR\x1b[39m %016X\n", f.s.foff)
		n, err = f.base.Read(dst[:])
		if n == BlockSize {
			f.s.foff += BlockSize
		} else {
			f.s.foff = badOffset
		}
	} else {
		// fmt.Printf("  r\x1b[91mA\x1b[39m %016X \x1b[90m!= %016X\x1b[39m\n", f.s.foff, idx*BlockSize)
		n, err = f.base.ReadAt(dst[:], int64(idx*BlockSize))
	}

	if err != nil { return err }
	if n != BlockSize {
		return JosefError{m: "Could not read entire block"}
	}
	
	f.cipher.Decrypt(dst[:], dst[:])
	
	var mask [BlockSize]byte
	f.blockMask(&mask, idx)
	for i, b := range mask {
		dst[i] ^= b
	}
	
	return nil
}

func (f *File) writeBlockAt(src *[BlockSize]byte, idx uint64) error {
	var block [BlockSize]byte
	copy(block[:], src[:])
	
	var mask [BlockSize]byte
	f.blockMask(&mask, idx)
	for i, b := range mask {
		block[i] ^= b
	}
	
	f.cipher.Encrypt(block[:], block[:])

	var n int
	var err error
	
	// Tries sequential Write(), or defaults to WriteAt()
	if f.s.foff == idx*BlockSize {
		// fmt.Printf("  w\x1b[92mR\x1b[39m %016X\n", f.s.foff)
		n, err = f.base.Write(block[:])
		if n == BlockSize {
			f.s.foff += BlockSize
		} else {
			f.s.foff = badOffset
		}
	} else {
		// fmt.Printf("  w\x1b[91mA\x1b[39m %016X \x1b[90m!= %016X\x1b[39m\n", f.s.foff, idx*BlockSize)
		n, err = f.base.WriteAt(block[:], int64(idx*BlockSize))
	}

	if err != nil { return err }
	
	if n != BlockSize {
		return JosefError{m: "Could not write entire block"}
	}
	
	return nil
}

func (f File) Close() error {
	debug(f.log, "Close()")
	return f.base.Close()
}

func (f File) Read(p []byte) (int, error) {
	debug(f.log, "Read([%d]{...})", len(p))

	if f.s.off >= f.s.size {
		return 0, io.EOF
	}

	if len(p) == 0 {
		return 0, nil
	}

	var err error
	var block [BlockSize]byte

	read := uint64(0)
	
	// read non block-aligned data
	if f.s.off%BlockSize != 0 {
		err = f.readBlockAt(&block, f.s.off/BlockSize+1)
		if err != nil { return int(read), err }
		n := uint64(copy(p, block[:]))
		f.s.off += n
		read += n
		p = p[n:]
		if f.s.off >= f.s.size {
			return int(read), nil
		}
	}

	// ensure p is not exceeding file size
	if uint64(len(p)) > f.s.off+f.s.size {
		p = p[:f.s.size-f.s.off]
	}

	if len(p) == 0 {
		return int(read), nil
	}

	// read remaining block-aligned data
	err = f.beginSeqAt(f.s.off+BlockSize)
	if err != nil { return 0, err }
	i := uint64(0)
	for i < uint64(len(p)) {
		err = f.readBlockAt(&block, f.s.off/BlockSize+1)
		if err != nil { return int(read), err }
		n := uint64(copy(p[i:], block[:]))
		f.s.off += n
		read += n
		i += n
	}

	return int(read), nil
}

func (f File) ReadAt(p []byte, off int64) (int, error) {
	debug(f.log, "ReadAt([%d], %d)", len(p), off)

	baseOff := f.s.off

	var err error
	var n int
	off, err = f.Seek(off, 0)
	if err != nil {
		return 0, err
	}

	n, err = f.Read(p)

	f.s.off = baseOff

	return n, err
}

func (f File) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	case 0: // file start
		debug(f.log, "Seek(%d)", offset)
		if offset < 0 {
			return int64(f.s.off), JosefError{m: "Negative offset is not valid for absolute whence"}
		}
		f.s.off = uint64(offset)
		return offset, nil
	case 1: // current
		if offset == 0 {
			return int64(f.s.off), nil
		}
		return f.Seek(int64(f.s.off) + offset, 0)
	case 2: // file end
		return f.Seek(int64(f.s.size) + offset, 0)
	default:
		return int64(f.s.off), JosefError{m: "Invalid whence"}
	}
}

func (f File) Write(p []byte) (int, error) {
	debug(f.log, "Write([%d]{...})", len(p))
	
	var err error
	var block [BlockSize]byte
	
	idx := f.s.off/BlockSize
	
	// write missing in-between blocks
	{
		lastIdx := f.s.size/BlockSize
		if idx > lastIdx {
			{
				lastRest := f.s.size%BlockSize
				if lastRest != 0 {
					err = f.readBlockAt(&block, lastIdx+1)
					if err != nil { return 0, err }
					for i := lastRest; i < BlockSize; i++ {
						block[i] = 0
					}
					err = f.writeBlockAt(&block, lastIdx+1)
					if err != nil { return 0, err }
					clear(block[:])
				}
			}
			for off := range idx - lastIdx - 1 {
				err = f.writeBlockAt(&block, lastIdx+off+2)
				if err != nil { return 0, err }
			}
			f.s.size = idx*BlockSize
		} else if (f.s.off < f.s.size) {
			err = f.readBlockAt(&block, idx+1)
			if err != nil { return 0, err }
		}
	}

	off := uint64(0)
	
	// write non block-aligned data
	{
		base := f.s.off%BlockSize
		rest := (BlockSize-base)%BlockSize
		if base != 0 {
			n := uint64(copy(block[base:], p))
			err = f.writeBlockAt(&block, f.s.off/BlockSize+1)
			f.s.off += n
			off += n
			if f.s.off > f.s.size {
				f.s.size = f.s.off
			}
			if err != nil { return 0, err }
			if uint64(len(p)) <= rest {
				err = f.storeMeta()
				if err != nil { return 0, err }
				return len(p), nil
			}
		}
	}
	
	// write remaining block-aligned data
	if off < uint64(len(p)) {
		err = f.beginSeqAt(f.s.off+BlockSize)
		if err != nil { return 0, err }
		for off < uint64(len(p)) {
			if len(p[off:]) < len(block) {
				f.readBlockAt(&block, f.s.off/BlockSize+1)
			}
			n := uint64(copy(block[:], p[off:]))
			err = f.writeBlockAt(&block, f.s.off/BlockSize+1)
			f.s.off += n
			off += n
			if f.s.off > f.s.size {
				f.s.size = f.s.off
			}
			if err != nil { return 0, err }
			if len(p) < BlockSize {
				break
			}
		}
	}
	
	err = f.storeMeta()
	if err != nil { return 0, err }
	
	return len(p), nil
}

func (f File) WriteAt(p []byte, off int64) (int, error) {
	debug(f.log, "WriteAt([%d]{...}, %d)", len(p), off)

	baseOff := f.s.off

	var err error
	var n int

	off, err = f.Seek(off, 0)
	if err != nil {
		return 0, err
	}
	
	n, err = f.Write(p)

	f.s.off = baseOff

	return n, err
}

func (f File) Name() string {
	debug(f.log, "Name()")
	return filepath.Base(f.path)
}

func (f File) Readdir(count int) ([]os.FileInfo, error) {
	debug(f.log, "Readdir(%d)", count)
	items, err := f.base.Readdir(count)
	if err != nil {
		return nil, err
	}
	for i, it := range items {
		actual, err := decipherPath(f.key, filepath.Join(cipherPath(f.key, f.path), it.Name()))
		if err != nil {
			return nil, err
		}
		items[i] = wrapFileInfo(filepath.Base(actual), it)
	}
	return items, nil
}

func (f File) Readdirnames(n int) ([]string, error) {
	debug(f.log, "Readdirnames(%d)", n)
	items, err := f.base.Readdirnames(n)
	if err != nil {
		return nil, err
	}
	for i, it := range items {
		actual, err := decipherPath(f.key, filepath.Join(cipherPath(f.key, f.path), it))
		if err != nil {
			return nil, err
		}
		items[i] = filepath.Base(actual)
	}
	return items, nil
}

func (f File) Stat() (os.FileInfo, error) {
	debug(f.log, "Stat()")
	stat, err := f.base.Stat()
	if err != nil {
		return nil, err
	}
	return wrapFileInfo(filepath.Base(f.path), stat), nil
}

func (f File) Sync() error {
	debug(f.log, "Sync()")
	return f.base.Sync()
}

func (f File) Truncate(size int64) error {
	debug(f.log, "Truncate(%d)", size)
	if size < 0 {
		return JosefError{m: "Can't truncate to negative size"}
	} else {
		size := uint64(size)
		if size == f.s.size { // nop
			return nil
		}
		var err error
		var block [BlockSize]byte
		nBlocks := roundup(size, BlockSize)
		if nBlocks == roundup(f.s.size, BlockSize) { // only last block affected
			if size > f.s.size { // need to add null bytes
				idx := size/BlockSize+1
				err = f.readBlockAt(&block, idx)
				if err != nil { return err }
				clear(block[f.s.size%BlockSize:size%BlockSize])
				err = f.writeBlockAt(&block, idx)
				if err != nil { return err }
			}
			f.s.size = size
			return f.storeMeta()
		} else if size < f.s.size { // need to shrink
			f.s.size = size
			err = f.storeMeta()
			if err != nil { return err }
			return f.base.Truncate(int64(BlockSize + nBlocks))
		} else { // need to append null blocks
			{
				base := f.s.size%BlockSize
				if base != 0 {
					idx := f.s.size/BlockSize+1
					err = f.readBlockAt(&block, idx)
					if err != nil { return err }
					err = f.beginSeqAt(idx*BlockSize)
					if err != nil { return err }
					clear(block[base:])
					err = f.writeBlockAt(&block, idx)
					if err != nil { return err }
					clear(block[:base])
					f.s.size = idx * BlockSize
				} else {
					err = f.beginSeqAt(f.s.size+BlockSize)
					if err != nil { return err }
				}
			}
			final := ceildiv(size, BlockSize)
			for idx := f.s.size/BlockSize; idx < final; idx += 1 {
				err = f.writeBlockAt(&block, idx+1)
				if err != nil { return err }
			}
			f.s.size = size
			return f.storeMeta()
		}
	}
}

func (f File) WriteString(s string) (int, error) {
	debug(f.log, "WriteString(%s)", s)
	return f.Write([]byte(s))
}

func wrapFile(log *slog.Logger, key [KeySize]byte, path string, base afero.File, new bool) (File, error) {
	cipher, err := aes.NewCipher(key[:32])
	if err != nil {
		return File{}, err
	}
	file := File{
		log: log,
		key: key,
		path: path,
		base: base,

		cipher: cipher,

		s: &fileState{
			size: 0,
			off: 0,
			foff: 0,
		},
	}
	var info os.FileInfo
	info, err = file.base.Stat()
	if err != nil {
		return File{}, err
	}
	if !info.IsDir() {
		err = file.init(new)
		if err != nil {
			return File{}, err
		}
	}
	return file, nil
}

type FileInfo struct {
	name string
	base os.FileInfo
}

func (i FileInfo) Name() string {
	return i.name
}

func (i FileInfo) Size() int64 {
	return i.base.Size()
}

func (i FileInfo) Mode() os.FileMode {
	return i.base.Mode()
}

func (i FileInfo) ModTime() time.Time {
	return i.base.ModTime()
}

func (i FileInfo) IsDir() bool {
	return i.base.IsDir()
}

func (i FileInfo) Sys() any {
	return i.base.Sys()
}

func wrapFileInfo(name string, base os.FileInfo) FileInfo {
	return FileInfo{
		name: name,
		base: base,
	}
}
