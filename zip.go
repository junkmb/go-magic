package magic

import (
	"archive/zip"
	"encoding/xml"
	"io"
	"io/ioutil"
	"strings"
)

type DetectionFunc func(io.Reader) string

var zipDetectionMap = map[string]DetectionFunc{
	"[Content_Types].xml": detectOfficeX,
}

func DetectZipExtension(reader io.ReaderAt, length int64) (string, error) {
	r, err := zip.NewReader(reader, length)
	if err != nil {
		return "", err
	}
	for _, f := range r.File {
		df, ok := zipDetectionMap[f.Name]
		if !ok {
			continue
		}

		fp, err := f.Open()
		if err != nil {
			return "", err
		}
		defer fp.Close()
		if ext := df(fp); ext != "" {
			return ext, nil
		}
	}
	return "zip", nil
}

func detectOfficeX(r io.Reader) string {
	b, err := ioutil.ReadAll(r)
	if err != nil {
		return ""
	}

	// Parse xml
	var o officeX
	if err := xml.Unmarshal(b, &o); err != nil {
		return ""
	}
	if len(o.Overrides) == 0 {
		return ""
	}

	pnFactors := strings.Split(o.Overrides[0].PartName, "/")
	if len(pnFactors) < 2 {
		return ""
	}
	switch pnFactors[1] {
	case "word":
		return "docx"
	case "xl":
		return "xlsx"
	case "ppt":
		return "pptx"
	}
	return ""

}

type officeX struct {
	Overrides []*override `xml:"Override"`
}

type override struct {
	PartName string `xml:"PartName,attr"`
}
