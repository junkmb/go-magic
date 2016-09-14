package magic

import (
	"io/ioutil"
	"path"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

var sampleDir = "./testdata"

func TestDetectExtension(t *testing.T) {
	d, err := ioutil.ReadDir(sampleDir)
	if err != nil {
		panic(err)
	}

	for _, f := range d {
		if !f.Mode().IsRegular() {
			continue
		}
		b, err := ioutil.ReadFile(path.Join(sampleDir, f.Name()))
		if err != nil {
			panic(err)
		}

		fnameFactor := strings.Split(f.Name(), ".")
		sampleExt := fnameFactor[len(fnameFactor)-1]
		switch sampleExt {
		case "docx", "xlsx", "pptx", "jar":
			sampleExt = "zip"
		case "txt":
			sampleExt = ""
		default:
		}
		ext := DetectExtension(b)
		t.Log(f.Name(), ext)

		assert.Equal(t, sampleExt, ext)
	}
}
