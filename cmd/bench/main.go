package main

// Writes 1GB of random data to an in-memory file
// and creates a [pprof](https://github.com/google/pprof) `bench.prof` file

import (
	"crypto/rand"
	"fmt"
	"josef"
	"os"
	"runtime/pprof"

	"github.com/spf13/afero"
)

func main() {
	fs := josef.CreateFS(nil, afero.NewMemMapFs(), [64]byte{})
	bytes := make([]byte, 1_000_000_000)
	rand.Read(bytes)

	{
		f, err := os.Create("bench.prof")
        if err != nil { panic(err) }
		defer f.Close()
		err = pprof.StartCPUProfile(f)
        if err != nil { panic(err) }
		defer pprof.StopCPUProfile()
	}

	{
		f, err := fs.OpenFile("foo.txt", os.O_WRONLY | os.O_CREATE | os.O_TRUNC, 0o700)
		if err != nil { panic(err) }
		var n int
		n, err = f.Write(bytes)
		if err != nil { panic(err) }
		fmt.Printf("Write() -> %d\n", n)
	}
}

