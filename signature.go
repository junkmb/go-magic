package magic

import (
	"bytes"
	"strconv"
	"strings"
)

var MIMEMap = map[string]string{
	"jpg":   "image/jpeg",
	"png":   "image/png",
	"gif":   "image/gif",
	"exe":   "application/octet-stream",
	"sys":   "application/octet-stream",
	"com":   "application/octet-stream",
	"dll":   "application/x-msdownload",
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
var definitions = []*definition{
	&definition{"jpg", []*signature{&signature{bytes: "FF D8 FF"}}}, // It appears that one can safely say that all JPEG files start with the three hex digits 0xFF-D8-FF.
	&definition{"png", []*signature{&signature{bytes: "89 50 4E 47 0D 0A 1A 0A"}}},
	&definition{"gif", []*signature{&signature{bytes: "47 49 46 38 37 61"}}},
	&definition{"gif", []*signature{&signature{bytes: "47 49 46 38 39 61"}}},
	&definition{"doc", []*signature{&signature{bytes: "D0 CF 11 E0 A1 B1 1A E1"}, &signature{offset: 512, bytes: "EC A5 C1 00"}}},
	&definition{"doc", []*signature{&signature{bytes: "DB A5 2D 00"}}},
	&definition{"doc", []*signature{&signature{bytes: "CF 11 E0 A1 B1 1A E1 00"}}},
	&definition{"doc", []*signature{&signature{bytes: "0D 44 4F 43"}}},
	&definition{"ppt", []*signature{&signature{bytes: "D0 CF 11 E0 A1 B1 1A E1"}, &signature{offset: 512, bytes: "A0 46 1D F0"}}},
	&definition{"ppt", []*signature{&signature{bytes: "D0 CF 11 E0 A1 B1 1A E1"}, &signature{offset: 512, bytes: "FD FF FF FF"}, &signature{offset: 518, bytes: "00 00"}}},
	&definition{"ppt", []*signature{&signature{bytes: "D0 CF 11 E0 A1 B1 1A E1"}, &signature{offset: 512, bytes: "00 6E 1E F0"}}},
	&definition{"ppt", []*signature{&signature{bytes: "D0 CF 11 E0 A1 B1 1A E1"}, &signature{offset: 512, bytes: "0F 00 E8 03"}}},
	&definition{"xls", []*signature{&signature{bytes: "D0 CF 11 E0 A1 B1 1A E1"}, &signature{offset: 512, bytes: "FD FF FF FF"}, &signature{offset: 517, bytes: "00"}}},
	&definition{"xls", []*signature{&signature{bytes: "D0 CF 11 E0 A1 B1 1A E1"}, &signature{offset: 512, bytes: "FD FF FF FF"}, &signature{offset: 517, bytes: "02"}}},
	&definition{"xls", []*signature{&signature{bytes: "D0 CF 11 E0 A1 B1 1A E1"}, &signature{offset: 512, bytes: "FD FF FF FF 20 00 00 00"}}},
	&definition{"xls", []*signature{&signature{bytes: "D0 CF 11 E0 A1 B1 1A E1"}, &signature{offset: 512, bytes: "09 08 10 00 00 06 05 00"}}},
	&definition{"xls", []*signature{&signature{bytes: "D0 CF 11 E0 A1 B1 1A E1"}}},
	&definition{"exe", []*signature{&signature{bytes: "4D 5A"}}}, // dll, scr, ocx, cpl and com are also.
	// &definition{"dll", []*signature{&signature{bytes: "4D 5A"}}},
	// &definition{"scr", []*signature{&signature{bytes: "4D 5A"}}},
	// &definition{"ocx", []*signature{&signature{bytes: "4D 5A"}}},
	// &definition{"cpl", []*signature{&signature{bytes: "4D 5A"}}},
	// &definition{"com", []*signature{&signature{bytes: "4D 5A"}}},
	&definition{"cpl", []*signature{&signature{bytes: "DC DC"}}},
	&definition{"sys", []*signature{&signature{bytes: "E8"}}},
	&definition{"sys", []*signature{&signature{bytes: "E9"}}},
	&definition{"sys", []*signature{&signature{bytes: "EB"}}},
	&definition{"sys", []*signature{&signature{bytes: "FF"}}},
	// &definition{"com", []*signature{&signature{bytes: "E8"}}},
	// &definition{"com", []*signature{&signature{bytes: "E9"}}},
	// &definition{"com", []*signature{&signature{bytes: "EB"}}},
	&definition{"pdf", []*signature{&signature{bytes: "25 50 44 46"}}},
	&definition{"swf", []*signature{&signature{bytes: "43 57 53"}}},
	&definition{"swf", []*signature{&signature{bytes: "46 57 53"}}},
	&definition{"swf", []*signature{&signature{bytes: "5A 57 53"}}},
	&definition{"rtf", []*signature{&signature{bytes: "7B 5C 72 74 66 31"}}},
	&definition{"jar", []*signature{&signature{bytes: "4A 41 52 43 53 00"}}},
	&definition{"jar", []*signature{&signature{bytes: "50 4B 03 04 14 00 08 00 08 00"}}},
	&definition{"jar", []*signature{&signature{bytes: "5F 27 A8 89"}}},
	&definition{"zip", []*signature{&signature{bytes: "50 4B 03 04"}}},
	&definition{"zip", []*signature{&signature{bytes: "50 4B 05 06"}}},
	&definition{"zip", []*signature{&signature{bytes: "50 4B 07 08"}}},
	&definition{"rar", []*signature{&signature{bytes: "52 61 72 21 1A 07 00"}}},
	&definition{"rar", []*signature{&signature{bytes: "52 61 72 21 1A 07 01 00"}}},
	&definition{"7z", []*signature{&signature{bytes: "37 7A BC AF 27 1C"}}},
	&definition{"cab", []*signature{&signature{bytes: "4D 53 43 46"}}},
	&definition{"cab", []*signature{&signature{bytes: "49 53 63 28"}}},
	&definition{"class", []*signature{&signature{bytes: "CA FE BA BE"}}},
}

type definition struct {
	extension  string
	signatures []*signature
}

type signature struct {
	offset int
	bytes  string
	b      []byte
}

func (s *signature) parse() error {
	bs := strings.Split(s.bytes, " ")
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

func DetectExtention(b []byte) string {
defLoop:
	for _, d := range definitions {
		for _, s := range d.signatures {
			sigLen := len(s.b)
			if len(b) < s.offset+sigLen || !bytes.Equal(b[s.offset:s.offset+sigLen], s.b) {
				continue defLoop
			}
		}
		return d.extension
	}
	return ""
}

func DetectMIME(b []byte) string {
	ext := DetectExtention(b)
	if ext == "" {
		return ext
	}
	return MIMEMap[ext]
}

func init() {
	for _, d := range definitions {
		for _, s := range d.signatures {
			if err := s.parse(); err != nil {
				panic(err)
			}
		}
	}
}
