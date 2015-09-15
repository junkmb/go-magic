package magic

import (
	"strconv"
	"strings"
)

var MIMEMap = map[string]string{
	"jpg":   "image/jpeg",
	"png":   "image/png",
	"gif":   "image/gif",
	"exe":   "application/x-msdownload",
	"dll":   "application/x-msdownload",
	"sys":   "application/octet-stream",
	"com":   "application/octet-stream",
	"cpl":   "application/octet-stream",
	"scr":   "application/x-rasmol",
	"ocx":   "application/x-msdownload",
	"doc":   "application/msword",
	"xls":   "application/vnd.ms-excel",
	"ppt":   "application/vnd.ms-powerpoint",
	"docx":  "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
	"xlsx":  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
	"pptx":  "application/vnd.openxmlformats-officedocument.presentationml.presentation",
	"pdf":   "application/pdf",
	"swf":   "application/x-shockwave-flash",
	"rtf":   "application/rtf",
	"cab":   "application/vnd.ms-cab-compressed",
	"zip":   "application/zip",
	"7z":    "application/x-7z-compressed",
	"jar":   "application/java-archive",
	"rar":   "application/x-rar-compressed",
	"class": "application/java-vm",
}

// This definition according to http://www.garykessler.net/library/file_sigs.html
var Definitions = []*Definition{
	&Definition{"jpg", []*Signature{&Signature{Bytes: "FF D8 FF"}}}, // It appears that one can safely say that all JPEG files start with the three hex digits 0xFF-D8-FF.
	&Definition{"png", []*Signature{&Signature{Bytes: "89 50 4E 47 0D 0A 1A 0A"}}},
	&Definition{"gif", []*Signature{&Signature{Bytes: "47 49 46 38 37 61"}}},
	&Definition{"gif", []*Signature{&Signature{Bytes: "47 49 46 38 39 61"}}},
	&Definition{"doc", []*Signature{&Signature{Bytes: "D0 CF 11 E0 A1 B1 1A E1"}, &Signature{Offset: 512, Bytes: "EC A5 C1 00"}}},
	&Definition{"doc", []*Signature{&Signature{Bytes: "DB A5 2D 00"}}},
	&Definition{"doc", []*Signature{&Signature{Bytes: "CF 11 E0 A1 B1 1A E1 00"}}},
	&Definition{"doc", []*Signature{&Signature{Bytes: "0D 44 4F 43"}}},
	&Definition{"ppt", []*Signature{&Signature{Bytes: "D0 CF 11 E0 A1 B1 1A E1"}, &Signature{Offset: 512, Bytes: "A0 46 1D F0"}}},
	&Definition{"ppt", []*Signature{&Signature{Bytes: "D0 CF 11 E0 A1 B1 1A E1"}, &Signature{Offset: 512, Bytes: "FD FF FF FF"}, &Signature{Offset: 518, Bytes: "00 00"}}},
	&Definition{"ppt", []*Signature{&Signature{Bytes: "D0 CF 11 E0 A1 B1 1A E1"}, &Signature{Offset: 512, Bytes: "00 6E 1E F0"}}},
	&Definition{"ppt", []*Signature{&Signature{Bytes: "D0 CF 11 E0 A1 B1 1A E1"}, &Signature{Offset: 512, Bytes: "0F 00 E8 03"}}},
	&Definition{"xls", []*Signature{&Signature{Bytes: "D0 CF 11 E0 A1 B1 1A E1"}, &Signature{Offset: 512, Bytes: "FD FF FF FF"}, &Signature{Offset: 517, Bytes: "00"}}},
	&Definition{"xls", []*Signature{&Signature{Bytes: "D0 CF 11 E0 A1 B1 1A E1"}, &Signature{Offset: 512, Bytes: "FD FF FF FF"}, &Signature{Offset: 517, Bytes: "02"}}},
	&Definition{"xls", []*Signature{&Signature{Bytes: "D0 CF 11 E0 A1 B1 1A E1"}, &Signature{Offset: 512, Bytes: "FD FF FF FF 20 00 00 00"}}},
	&Definition{"xls", []*Signature{&Signature{Bytes: "D0 CF 11 E0 A1 B1 1A E1"}, &Signature{Offset: 512, Bytes: "09 08 10 00 00 06 05 00"}}},
	&Definition{"xls", []*Signature{&Signature{Bytes: "D0 CF 11 E0 A1 B1 1A E1"}}},
	&Definition{"exe", []*Signature{&Signature{Bytes: "4D 5A"}}}, // dll, scr, ocx, cpl and com are also.
	// &Definition{"dll", []*Signature{&Signature{Bytes: "4D 5A"}}},
	// &Definition{"scr", []*Signature{&Signature{Bytes: "4D 5A"}}},
	// &Definition{"ocx", []*Signature{&Signature{Bytes: "4D 5A"}}},
	// &Definition{"cpl", []*Signature{&Signature{Bytes: "4D 5A"}}},
	// &Definition{"com", []*Signature{&Signature{Bytes: "4D 5A"}}},
	&Definition{"cpl", []*Signature{&Signature{Bytes: "DC DC"}}},
	&Definition{"sys", []*Signature{&Signature{Bytes: "E8"}}},
	&Definition{"sys", []*Signature{&Signature{Bytes: "E9"}}},
	&Definition{"sys", []*Signature{&Signature{Bytes: "EB"}}},
	&Definition{"sys", []*Signature{&Signature{Bytes: "FF"}}},
	// &Definition{"com", []*Signature{&Signature{Bytes: "E8"}}},
	// &Definition{"com", []*Signature{&Signature{Bytes: "E9"}}},
	// &Definition{"com", []*Signature{&Signature{Bytes: "EB"}}},
	&Definition{"pdf", []*Signature{&Signature{Bytes: "25 50 44 46"}}},
	&Definition{"swf", []*Signature{&Signature{Bytes: "43 57 53"}}},
	&Definition{"swf", []*Signature{&Signature{Bytes: "46 57 53"}}},
	&Definition{"swf", []*Signature{&Signature{Bytes: "5A 57 53"}}},
	&Definition{"rtf", []*Signature{&Signature{Bytes: "7B 5C 72 74 66 31"}}},
	&Definition{"jar", []*Signature{&Signature{Bytes: "4A 41 52 43 53 00"}}},
	&Definition{"jar", []*Signature{&Signature{Bytes: "50 4B 03 04 14 00 08 00 08 00"}}},
	&Definition{"jar", []*Signature{&Signature{Bytes: "5F 27 A8 89"}}},
	&Definition{"zip", []*Signature{&Signature{Bytes: "50 4B 03 04"}}},
	&Definition{"zip", []*Signature{&Signature{Bytes: "50 4B 05 06"}}},
	&Definition{"zip", []*Signature{&Signature{Bytes: "50 4B 07 08"}}},
	&Definition{"rar", []*Signature{&Signature{Bytes: "52 61 72 21 1A 07 00"}}},
	&Definition{"rar", []*Signature{&Signature{Bytes: "52 61 72 21 1A 07 01 00"}}},
	&Definition{"7z", []*Signature{&Signature{Bytes: "37 7A BC AF 27 1C"}}},
	&Definition{"cab", []*Signature{&Signature{Bytes: "4D 53 43 46"}}},
	&Definition{"cab", []*Signature{&Signature{Bytes: "49 53 63 28"}}},
	&Definition{"class", []*Signature{&Signature{Bytes: "CA FE BA BE"}}},
}

type Definition struct {
	Extension  string
	Signatures []*Signature
}

func (d *Definition) Parse() error {
	for _, s := range d.Signatures {
		if err := s.parse(); err != nil {
			return err
		}
	}
	return nil
}

type Signature struct {
	Offset int
	Bytes  string
	b      []byte
}

func (s *Signature) parse() error {
	bs := strings.Split(s.Bytes, " ")
	s.b = make([]byte, len(bs))
	for i, bStr := range bs {
		b, err := strconv.ParseUint(bStr, 16, 0)
		if err != nil {
			return err
		}
		s.b[i] = byte(b)
	}
	return nil
}

func DetectExtension(b []byte) string {
	return NODE.Match(b)
}

func DetectMIME(b []byte) string {
	ext := DetectExtension(b)
	if ext == "" {
		return ext
	}
	return MIMEMap[ext]
}

func init() {
	NODE = &Node{}
	for _, d := range Definitions {
		if err := d.Parse(); err != nil {
			panic(err)
		}
		NODE.Insert(d)
	}
}
