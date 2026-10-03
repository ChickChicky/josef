package josef

// afero.File implementation for Josef

// TODO: Add key and block size constants instead of always repeating/computing them

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/afero"
)

type fileState struct {
	// size of the file
	size uint64

	// TODO: implement proper buffering
	//
	// // buffer for read/write operations
	// buf []byte
	// // buffer block index
	// bufIdx uint64
	// // buffer data is irrelevant
	// bufStale bool

	// current offset
	off uint64
}

type File struct {
	log *slog.Logger
	key [64]byte
	path string
	base afero.File

	cipher cipher.Block
	
	s *fileState
}

// TODO: Optimize reads/writes

// initializes the file's state
func (f *File) init(new bool) error {
	// bs := f.cipher.BlockSize()
	var err error
	if new {
		// TODO: Ensure file indeed is empty
		f.s.size = 0
		err = f.storeMeta()
	} else {
		err = f.loadMeta()
	}
	if err != nil {
		return err
	}
	f.s.off = 0
	// f.s.buf = make([]byte, bs)
	// f.s.bufStale = true
	return nil
}

// Gets the mask for a block in the file
func (f *File) blockMask(idx uint64) []byte {
	bs := f.cipher.BlockSize()
	mask := make([]byte, bs)
	binary.BigEndian.PutUint64(mask, idx)
	for i := range ceildiv(bs, 8) {
		copy(mask[i*8+8:], mask[i*8:i*8+8])
	}
	// hash := sha512.New()
	// hs := hash.Size()
	// for i := range ceildiv(bs, hs) {
	// 	hash.Reset()
	// 	hash.Write(mask[i*hs:i*hs+hs])
	// 	copy(mask[i*hs:], hash.Sum(nil))
	// }
	f.cipher.Encrypt(mask, mask)
	return mask
}

func (f *File) loadMeta() error {
	meta := make([]byte, f.cipher.BlockSize())
	err := f.readBlockAt(meta, 0)
	if err != nil {
		return err
	}
	f.s.size = binary.BigEndian.Uint64(meta)
	return nil
}

func (f *File) storeMeta() error {
	meta := make([]byte, f.cipher.BlockSize())
	binary.BigEndian.PutUint64(meta, f.s.size)
	return f.writeBlockAt(meta, 0)
}

// // Number of valid bytes in the buf
// // so that `f.s.buf[:f.BufLen()]` is data actually present in the file
// func (f *File) BufLen() uint64 {
// 	if f.s.bufStale {
// 		return 0
// 	}
// 	bs := uint64(f.cipher.BlockSize())
// 	bc := ceildiv(f.s.size, bs)
// 	if f.s.bufIdx+1 < bc {
// 		return bs
// 	}
// 	if f.s.bufIdx >= bc {
// 		return 0
// 	}
// 	return f.s.size % bs
// }

func (f *File) readBlockAt(dst []byte, idx uint64) error {
	bs := f.cipher.BlockSize()
	if len(dst) < bs {
		return JosefError{m: "Destination too small"}
	}
	// // use cached block if available
	// if f.s.bufIdx == idx && !f.s.bufStale && len(f.s.buf) >= bs {
	// 	copy(dst, f.s.buf[:bs])
	// 	return nil
	// }
	n, err := f.base.ReadAt(dst[:bs], int64(idx*uint64(bs)))
	if err != nil {
		return err
	}
	if n != min(len(dst), bs) {
		return JosefError{m: "Could not read block"}
	}
	f.cipher.Decrypt(dst, dst)
	for i, b := range f.blockMask(idx) {
		dst[i] ^= b
	}
	return nil
}

func (f *File) writeBlockAt(src []byte, idx uint64) error {
	bs := f.cipher.BlockSize()
	block := make([]byte, bs)
	copy(block, src)
	for i, b := range f.blockMask(idx) {
		block[i] ^= b
	}
	f.cipher.Encrypt(block, block)
	_, err := f.base.WriteAt(block, int64(idx*uint64(bs)))
	return err
}

func (f File) Close() error {
	f.log.Debug("Close()")
	return f.base.Close()
}

func (f File) Read(p []byte) (int, error) {
	f.log.Debug(fmt.Sprintf("Read([%d]{...})", len(p)))

	if len(p) == 0 || f.s.off >= f.s.size {
		return 0, nil
	}

	// TODO: Read directly to p if large enough

	var err error
	
	bs := uint64(f.cipher.BlockSize())
	block := make([]byte, bs)

	read := uint64(0)
	
	// read non block-aligned data
	if f.s.off%bs != 0 {
		err = f.readBlockAt(block, f.s.off/bs+1)
		if err != nil { return int(read), err }
		n := uint64(copy(p, block))
		f.s.off += n
		read += n
		p = p[n:]
	}

	if f.s.off >= f.s.size {
		return int(read), nil
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
		err = f.readBlockAt(block, f.s.off/bs+1)
		if err != nil { return int(read), err }
		n := uint64(copy(p[i:], block))
		f.s.off += n
		read += n
		i += n
	}

	return int(read), nil
}

func (f File) ReadAt(p []byte, off int64) (int, error) {
	// f.log.Debug(fmt.Sprintf("ReadAt([%d], %d)", len(p), off))
	var err error
	off, err = f.Seek(off, 0)
	if err != nil {
		return 0, err
	}
	return f.Read(p)
}

func (f File) Seek(offset int64, whence int) (int64, error) {
	// bs := uint64(f.cipher.BlockSize())
	switch whence {
	case 0: // file start
		f.log.Debug(fmt.Sprintf("Seek(%d)", offset))
		// baseIdx := f.s.off/bs
		if offset < 0 {
			return int64(f.s.off), JosefError{m: "Negative offset is unsupported for absolute whence"}
		}
		off := uint64(offset)
		// seekIdx := off/bs
		// if baseIdx != seekIdx {
		// 	f.s.bufStale = true
		// 	f.s.bufIdx = 0
		// }
		f.s.off = off
		return int64(f.s.off), nil
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
	f.log.Debug(fmt.Sprintf("Write([%d]{...})", len(p)))
	
	var err error
	
	bs := uint64(f.cipher.BlockSize())
	idx := f.s.off/bs
	block := make([]byte, bs)
	
	// write missing in-between blocks
	{
		lastIdx := f.s.size/bs
		if idx > lastIdx {
			{
				lastRest := f.s.size%bs
				if lastRest != 0 {
					err = f.readBlockAt(block, lastIdx+1)
					if err != nil { return 0, err }
					for i := lastRest; i < bs; i++ {
						block[i] = 0
					}
					err = f.writeBlockAt(block, lastIdx+1)
					if err != nil { return 0, err }
					clear(block)
				}
			}
			// TODO: Optimize with Seek() + sequential writeBlockAs() calls
			for off := range idx - lastIdx - 1 {
				err = f.writeBlockAt(block, lastIdx+off+2)
				if err != nil { return 0, err }
			}
			f.s.size = idx*bs
		} else if (f.s.off < f.s.size) {
			err = f.readBlockAt(block, idx+1)
			if err != nil { return 0, err }
		}
	}

	off := uint64(0)
	
	// write non block-aligned data
	{
		base := f.s.off%bs
		rest := (bs-base)%bs
		if base != 0 {
			n := uint64(copy(block[base:], p))
			err = f.writeBlockAt(block, f.s.off/bs+1)
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
			f.readBlockAt(block, f.s.off/bs+1)
		}
		n := uint64(copy(block, p[off:]))
		err = f.writeBlockAt(block, f.s.off/bs+1)
		f.s.off += n
		off += n
		if f.s.off > f.s.size {
			f.s.size = f.s.off
		}
		if err != nil { return 0, err }
		if uint64(len(p)) < bs {
			break
		}
	}
	
	err = f.storeMeta()
	if err != nil { return 0, err }
	
	return len(p), nil
}

func (f File) WriteAt(p []byte, off int64) (int, error) {
	f.log.Debug(fmt.Sprintf("WriteAt([%d]{...}, %d)", len(p), off))
	var err error
	off, err = f.Seek(off, 0)
	if err != nil {
		return 0, err
	}
	return f.Write(p)
}

func (f File) Name() string {
	f.log.Debug("Name()")
	return filepath.Base(f.path)
}

func (f File) Readdir(count int) ([]os.FileInfo, error) {
	f.log.Debug(fmt.Sprintf("Readdir(%d)", count))
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
	f.log.Debug(fmt.Sprintf("Readdirnames(%d)", n))
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
	f.log.Debug("Stat()")
	stat, err := f.base.Stat()
	if err != nil {
		return nil, err
	}
	return wrapFileInfo(filepath.Base(f.path), stat), nil
}

func (f File) Sync() error {
	f.log.Debug("Sync()")
	return f.base.Sync()
}

func (f File) Truncate(size int64) error {
	f.log.Debug(fmt.Sprintf("Truncate(%d)", size))
	return JosefError{m: "Truncate not implemented"}
}

func (f File) WriteString(s string) (int, error) {
	f.log.Debug(fmt.Sprintf("WriteString(%s)", s))
	return f.Write([]byte(s))
}

func wrapFile(log *slog.Logger, key [64]byte, path string, base afero.File, new bool) (File, error) {
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

			// buf: []byte{},
			// bufIdx: 0,
			// bufStale: true,

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
