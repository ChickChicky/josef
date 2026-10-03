package josef

// afero.Fs implementation for Josef

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/afero"
)

type Fs struct { 
	log *slog.Logger
	key [64]byte
	base afero.Fs
}

// Create creates a file in the filesystem, returning the file and an error, if any happens.
func (d Fs) Create(name string) (afero.File, error) {
	d.log.Debug(fmt.Sprintf("Create(%q)", name))
	file, err := d.base.Create(cipherPath(d.key, name))
	if err != nil {
		return nil, err
	}
	return wrapFile(d.log.With("name", name), d.key, name, file, true)
}

// Mkdir creates a directory in the filesystem, return an error if any happens.
func (d Fs) Mkdir(name string, perm os.FileMode) error {
	d.log.Debug(fmt.Sprintf("Mkdir(%q, %03o)\n", name, perm))
	return d.base.Mkdir(cipherPath(d.key, name), perm)
}

// MkdirAll creates a directory path and all parents that does not exist yet.
func (d Fs) MkdirAll(path string, perm os.FileMode) error {
	d.log.Debug(fmt.Sprintf("MkdirAll(%q, %03o)", path, perm))
	return d.base.MkdirAll(cipherPath(d.key, path), perm)
}

// Open opens a file, returning it or an error, if any happens.
func (d Fs) Open(name string) (afero.File, error) {
	d.log.Debug(fmt.Sprintf("Open(%q)", name))
	file, err := d.base.Open(cipherPath(d.key, name))
	if err != nil {
		return nil, err
	}
	return wrapFile(d.log.With("name", name), d.key, name, file, false)
}

// OpenFile opens a file using the given flags and the given mode.
func (d Fs) OpenFile(name string, flag int, perm os.FileMode) (afero.File, error) {
	d.log.Debug(fmt.Sprintf("OpenFile(%q, %d, %03o)", name, flag, perm))
	if flag & os.O_APPEND != 0 { return nil, JosefError{m: "O_APPEND is not supported"} }
	if flag & os.O_CREATE != 0 { return nil, JosefError{m: "O_CREATE is not supported"} }
	if flag & os.O_EXCL   != 0 { return nil, JosefError{m: "O_EXCL is not supported"} }
	if flag & os.O_SYNC   != 0 { return nil, JosefError{m: "O_SYNC is not supported"} }
	if flag & os.O_TRUNC  != 0 { return nil, JosefError{m: "O_TRUNC is not supported"} }
	if flag & os.O_WRONLY != 0 {
		flag &= ^os.O_WRONLY
		flag |= os.O_RDWR
	}
	file, err := d.base.OpenFile(cipherPath(d.key, name), flag, perm)
	if err != nil {
		return nil, err
	}
	return wrapFile(d.log.With("name", name), d.key, name, file, false)
}

// Remove removes a file identified by name, returning an error, if any happens.
func (d Fs) Remove(name string) error {
	d.log.Debug(fmt.Sprintf("Remove(%q)", name))
	return d.base.Remove(cipherPath(d.key, name))
}

// RemoveAll removes a directory path and any children it contains. It does not fail if the path does not exist (return nil).
func (d Fs) RemoveAll(path string) error {
	d.log.Debug(fmt.Sprintf("RemoveAll(%q)", path))
	return d.base.RemoveAll(cipherPath(d.key, path))
}

// Rename renames a file.
func (d Fs) Rename(oldname, newname string) error {
	d.log.Debug(fmt.Sprintf("Rename(%q, %q)", oldname, newname))
	return d.base.Rename(cipherPath(d.key, oldname), cipherPath(d.key, newname))
}

// The name of this FileSystem
func (d Fs) Name() string {
	d.log.Debug("Name()")
	return "Erfs/" + d.base.Name()
}

// Chmod changes the mode of the named file to mode.
func (d Fs) Chmod(name string, mode os.FileMode) error {
	d.log.Debug(fmt.Sprintf("Chmod(%q, %03o)", name, mode))
	return d.base.Chmod(cipherPath(d.key, name), mode)
}

// Chown changes the uid and gid of the named file.
func (d Fs) Chown(name string, uid, gid int) error {
	d.log.Debug(fmt.Sprintf("Chown(%q, %d, %d)", name, uid, gid))
	return d.base.Chown(cipherPath(d.key, name), uid, gid)
}

// Chtimes changes the access and modification times of the named file
func (d Fs) Chtimes(name string, atime time.Time, mtime time.Time) error {
	d.log.Debug(fmt.Sprintf("Chtimes(%q, %s, %s)",name, atime.String(), mtime.String()))
	return d.base.Chtimes(cipherPath(d.key, name), atime, mtime)
}

// Stat returns a FileInfo describing the named file, or an error, if any happens.
func (d Fs) Stat(name string) (os.FileInfo, error) {
	d.log.Debug(fmt.Sprintf("Stat(%q)", name))
	info, err := d.base.Stat(cipherPath(d.key, name))
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
