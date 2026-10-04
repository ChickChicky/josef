package josef

// afero.Fs implementation for Josef

import (
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/afero"
)

type Fs struct { 
	log *slog.Logger
	key [KeySize]byte
	base afero.Fs
}

// Create creates a file in the filesystem, returning the file and an error, if any happens.
func (fs Fs) Create(name string) (afero.File, error) {
	debug(fs.log, "Create(%q)", name)
	file, err := fs.base.Create(cipherPath(fs.key, name))
	if err != nil {
		return nil, err
	}
	return wrapFile(fs.log.With("name", name), fs.key, name, file, true)
}

// Mkdir creates a directory in the filesystem, return an error if any happens.
func (fs Fs) Mkdir(name string, perm os.FileMode) error {
	debug(fs.log, "Mkdir(%q, %03o)\n", name, perm)
	return fs.base.Mkdir(cipherPath(fs.key, name), perm)
}

// MkdirAll creates a directory path and all parents that does not exist yet.
func (fs Fs) MkdirAll(path string, perm os.FileMode) error {
	debug(fs.log, "MkdirAll(%q, %03o)", path, perm)
	return fs.base.MkdirAll(cipherPath(fs.key, path), perm)
}

// Open opens a file, returning it or an error, if any happens.
func (fs Fs) Open(name string) (afero.File, error) {
	debug(fs.log, "Open(%q)", name)
	file, err := fs.base.Open(cipherPath(fs.key, name))
	if err != nil {
		return nil, err
	}
	return wrapFile(fs.log.With("name", name), fs.key, name, file, false)
}

// OpenFile opens a file using the given flags and the given mode.
func (fs Fs) OpenFile(name string, flag int, perm os.FileMode) (afero.File, error) {
	debug(fs.log, "OpenFile(%q, %d, %03o)", name, flag, perm)
	if flag & os.O_APPEND != 0 { return nil, JosefError{m: "O_APPEND is not supported"} }
	if flag & os.O_CREATE != 0 { return nil, JosefError{m: "O_CREATE is not supported"} }
	if flag & os.O_EXCL   != 0 { return nil, JosefError{m: "O_EXCL is not supported"} }
	if flag & os.O_SYNC   != 0 { return nil, JosefError{m: "O_SYNC is not supported"} }
	if flag & os.O_TRUNC  != 0 { return nil, JosefError{m: "O_TRUNC is not supported"} }
	if flag & os.O_WRONLY != 0 {
		flag &= ^os.O_WRONLY
		flag |= os.O_RDWR
	}
	file, err := fs.base.OpenFile(cipherPath(fs.key, name), flag, perm)
	if err != nil {
		return nil, err
	}
	return wrapFile(fs.log.With("name", name), fs.key, name, file, false)
}

// Remove removes a file identified by name, returning an error, if any happens.
func (fs Fs) Remove(name string) error {
	debug(fs.log, "Remove(%q)", name)
	return fs.base.Remove(cipherPath(fs.key, name))
}

// RemoveAll removes a directory path and any children it contains. It does not fail if the path does not exist (return nil).
func (fs Fs) RemoveAll(path string) error {
	debug(fs.log, "RemoveAll(%q)", path)
	return fs.base.RemoveAll(cipherPath(fs.key, path))
}

// Rename renames a file.
func (fs Fs) Rename(oldname, newname string) error {
	debug(fs.log, "Rename(%q, %q)", oldname, newname)
	return fs.base.Rename(cipherPath(fs.key, oldname), cipherPath(fs.key, newname))
}

// The name of this FileSystem
func (fs Fs) Name() string {
	debug(fs.log, "Name()")
	return "Josef/" + fs.base.Name()
}

// Chmod changes the mode of the named file to mode.
func (fs Fs) Chmod(name string, mode os.FileMode) error {
	debug(fs.log, "Chmod(%q, %03o)", name, mode)
	return fs.base.Chmod(cipherPath(fs.key, name), mode)
}

// Chown changes the uid and gid of the named file.
func (fs Fs) Chown(name string, uid, gid int) error {
	debug(fs.log, "Chown(%q, %d, %d)", name, uid, gid)
	return fs.base.Chown(cipherPath(fs.key, name), uid, gid)
}

// Chtimes changes the access and modification times of the named file
func (fs Fs) Chtimes(name string, atime time.Time, mtime time.Time) error {
	debug(fs.log, "Chtimes(%q, %s, %s)",name, atime.String(), mtime.String())
	return fs.base.Chtimes(cipherPath(fs.key, name), atime, mtime)
}

// Stat returns a FileInfo describing the named file, or an error, if any happens.
func (fs Fs) Stat(name string) (os.FileInfo, error) {
	debug(fs.log, "Stat(%q)", name)
	info, err := fs.base.Stat(cipherPath(fs.key, name))
	if err != nil {
		return nil, err
	}
	return wrapFileInfo(filepath.Base(name), info), err
}

// Creates an encrypted overlay on top of an existing file system
// (key is owned by the caller and copied by the function)
func CreateFS(log *slog.Logger, base afero.Fs, key [64]byte) Fs {
	fs := Fs{
		log: log,
		base: base,
	}
	copy(fs.key[:], key[:])
	return fs
}
