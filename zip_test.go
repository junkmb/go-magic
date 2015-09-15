package magic

import (
	"bytes"
	"io/ioutil"
	"path"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDetectZipExtension(t *testing.T) {
	d, err := ioutil.ReadDir(sampleDir)
	if err != nil {
		panic(err)
	}

	for _, f := range d {
		fnameFactor := strings.Split(f.Name(), ".")
		sampleExt := fnameFactor[len(fnameFactor)-1]
		switch sampleExt {
		case "zip", "docx", "xlsx", "pptx":
		default:
			continue
		}

		b, err := ioutil.ReadFile(path.Join(sampleDir, f.Name()))
		if err != nil {
			panic(err)
		}
		ext, err := DetectZipExtension(bytes.NewReader(b), int64(len(b)))
		if err != nil {
			panic(err)
		}
		t.Log(f.Name(), ext)

		assert.Equal(t, sampleExt, ext)
	}
}
