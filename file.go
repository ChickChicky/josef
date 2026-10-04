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

type fileState struct {
	// size of the file
	size uint64
	// current offset
	off uint64
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

func (f *File) storeMeta() error {
	var meta [BlockSize]byte
	binary.BigEndian.PutUint64(meta[:], f.s.size)
	copy(meta[8:], f.salt[:])
	return f.writeBlockAt(&meta, 0)
}

func (f *File) readBlockAt(dst *[BlockSize]byte, idx uint64) error {
	n, err := f.base.ReadAt(dst[:BlockSize], int64(idx*BlockSize))
	if err != nil { return err }
	if n != BlockSize {
		return JosefError{m: "Could not read block"}
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
	_, err := f.base.WriteAt(block[:], int64(idx*BlockSize))
	
	return err
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
	var err error
	off, err = f.Seek(off, 0)
	if err != nil {
		return 0, err
	}
	return f.Read(p)
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
	
	err = f.storeMeta()
	if err != nil { return 0, err }
	
	return len(p), nil
}

func (f File) WriteAt(p []byte, off int64) (int, error) {
	debug(f.log, "WriteAt([%d]{...}, %d)", len(p), off)
	var err error
	off, err = f.Seek(off, 0)
	if err != nil {
		return 0, err
	}
	return f.Write(p)
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
	return JosefError{m: "Truncate not implemented"}
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
