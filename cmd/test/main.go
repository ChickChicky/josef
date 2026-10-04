package main

// Runs some simple tests to ensure proper Write() and WriteAt() functionality

import (
	"fmt"
	"io"
	"josef"
	"log/slog"
	"os"
	"reflect"

	"github.com/spf13/afero"
)

func test(fs afero.Fs, run func(file afero.File) error, expected []byte) {
	file, err := fs.OpenFile("test", os.O_RDWR | os.O_CREATE | os.O_TRUNC, 0o600)
	if err != nil { panic(err) }
		err = run(file)
		if err != nil { panic(err) }
	file.Close()

	collected := []byte{}
	file, err = fs.OpenFile("test", os.O_RDONLY, 0o600)
	if err != nil { panic(err) }
		var n int
		buf := make([]byte, 512)
		for {
			n, err = file.Read(buf)
			if err != nil { 
				if err == io.EOF {
					break
				}
				panic(err) 
			}
			if n == 0 {
				break
			}
			collected = append(collected, buf[:n]...)
		}
	file.Close()
	
	if !reflect.DeepEqual(collected, expected) {
		// {
		// 	file, err = fs.OpenFile("test", os.O_RDONLY, 0o600)
		// 	if err != nil { panic(err) }
		// 	file := file.(josef.File)
		// 	bs := uint64(file.cipher.BlockSize())
		// 	block := make([]byte, bs)
		// 	fmt.Print(" ==> ")
		// 	for i := range ceildiv(file.s.size, bs) {
		// 		err = file.ReadBlockAt(block, i+1)
		// 		if err != nil { panic(err) }
		// 		fmt.Printf("%q ", block)
		// 	}
		// 	fmt.Print("\n")
		// 	file.Close()
		// }
		fmt.Printf(" --- %q != ---\n     %q\n", collected, expected)
		panic("oh no!")
	}

	fmt.Printf(" --- %q ok ---\n", expected)
}

func main() { slog.SetLogLoggerLevel(slog.LevelDebug)
	base := afero.NewMemMapFs()

	fs := josef.CreateFS(slog.Default(), base, [64]byte{})

	test(fs, 
		func(file afero.File) error {
			return nil
		}, 
		[]byte(""),
	)

	test(fs, 
		func(file afero.File) error {
			if _, err := file.Write([]byte("foo")); err != nil { panic(err) }
			return nil
		}, 
		[]byte("foo"),
	)

	test(fs, 
		func(file afero.File) error {
			if _, err := file.Write([]byte("itspansoneblock!")); err != nil { panic(err) }
			return nil
		}, 
		[]byte("itspansoneblock!"),
	)

	test(fs, 
		func(file afero.File) error {
			if _, err := file.Write([]byte("whileindeedthisfiledoestakesupmanyblocks!")); err != nil { panic(err) }
			return nil
		}, 
		[]byte("whileindeedthisfiledoestakesupmanyblocks!"),
	)

	test(fs, 
		func(file afero.File) error {
			if _, err := file.Write([]byte("Hello, foo!")); err != nil { panic(err) }
			if _, err := file.WriteAt([]byte("bar"), 7); err != nil { panic(err) }
			return nil
		}, 
		[]byte("Hello, bar!"),
	)

	test(fs, 
		func(file afero.File) error {
			if _, err := file.Write([]byte("--------------Welcome, foo!")); err != nil { panic(err) }
			if _, err := file.WriteAt([]byte("somereallysmol"), 0); err != nil { panic(err) }
			return nil
		}, 
		[]byte("somereallysmolWelcome, foo!"),
	)

	test(fs, 
		func(file afero.File) error {
			if _, err := file.Write([]byte("----------------------------------------------------------------")); err != nil { panic(err) }
			if _, err := file.WriteAt([]byte("neartheboundaryandspansmultipleblocks"), 10); err != nil { panic(err) }
			return nil
		}, 
		[]byte("----------neartheboundaryandspansmultipleblocks-----------------"),
	)
}
