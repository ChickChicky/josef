# Josef (Just One Simple Encrypted File system)

Provides an [afero](https://github.com/spf13/afero)-compatible encrypted filesystem implementation

## Example usage

```go
base := afero.NewMemMapFs()

// Create a Josef overlay on top of the base file system
key := [64]byte{ /* load a cryptographically secure key */ }
fs := josef.CreateFS(slog.Default(), base, key)

// Data is scoped per key, so we need to create the "root" folder
fs.MkdirAll("/", 0o700)

var err error
var file afero.File
var n int

// Write some data to a file...
{
    file, err = fs.Create("example.txt")
    if err != nil { panic(err) }

    n, err = file.Write([]byte("Hello, world!\n"))
    if err != nil { panic(err) }
    if n != 14 { panic("Could not write everything") }

    file.Close()
}

// And read it back!
{
    file, err = fs.OpenFile("example.txt", os.O_RDONLY, 0o600)
    if err != nil { panic(err) }

    buf := [14]byte{}

    n, err = file.Read(buf[:])
    if err != nil { panic(err) }
    if n != 14 { panic("Could not read everything") }
    
    file.Close()

    fmt.Printf("Read() -> %q\n", buf)
    // Read() -> "Hello, world!\n"
}
```

## Caveats

* **Behaviour may change at any time**
* Not externally audited, probably quite weak ryptographically speaking but should be better than nothing
* Poorly optimized
* Frequently reads from the underlying filesystem
    * `CacheOnReadFs` with `MemMapFs` might be a good idea if read operations are especially costly
* `Fs.OpenFile()` does not support flags:
    * `os.O_APPEND`/`os.O_CREATE`/`os.O_EXCL`/`os.O_SYNC`/`os.O_TRUNC`
    * `os.O_WRONLY` is not supported as it needs to read from the file (quietly replaces it with os.O_RDWR)
