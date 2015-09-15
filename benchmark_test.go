package magic

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"path"
	"strings"
	"testing"
)

type File struct {
	Extension string
	Bytes     []byte
}

func BenchmarkDetectExtensionWithLoop(b *testing.B) {
	b.StopTimer()
	files := readFiles()
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		for _, f := range files {
			ext := detectWithLoop(f.Bytes)
			if f.Extension != ext {
				errMsg := fmt.Sprintf("Detect with loop missed: %s, %s", f.Extension, ext)
				panic(errMsg)
			}
		}
	}
}

func BenchmarkDetectExtension(b *testing.B) {
	b.StopTimer()
	files := readFiles()
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		for _, f := range files {
			ext := DetectExtension(f.Bytes)
			if f.Extension != ext {
				errMsg := fmt.Sprintf("Detect Extension missed: %s, %s", f.Extension, ext)
				panic(errMsg)
			}
		}
	}
}

func readFiles() []*File {
	d, err := ioutil.ReadDir(sampleDir)
	if err != nil {
		panic(err)
	}

	files := make([]*File, len(d))

	for i, f := range d {
		b, err := ioutil.ReadFile(path.Join(sampleDir, f.Name()))
		if err != nil {
			panic(err)
		}
		fnameFactor := strings.Split(f.Name(), ".")
		sampleExt := fnameFactor[len(fnameFactor)-1]
		switch sampleExt {
		case "docx", "xlsx", "pptx":
			sampleExt = "zip"
		case "txt":
			sampleExt = ""
		default:
		}
		f := &File{Extension: sampleExt, Bytes: b}
		files[i] = f
	}
	return files
}

func detectWithLoop(b []byte) string {
defLoop:
	for _, d := range Definitions {
		for _, s := range d.Signatures {
			sigLen := len(s.b)
			if len(b) < s.Offset+sigLen || !bytes.Equal(b[s.Offset:s.Offset+sigLen], s.b) {
				continue defLoop
			}
		}
		return d.Extension
	}
	return ""
}
