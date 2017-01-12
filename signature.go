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
	"exe":   "application/x-msdownload",
	"dll":   "application/x-msdownload",
	"sys":   "application/x-msdownload",
	"com":   "application/x-msdownload",
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
	"tar.z": "application/x-compress",
	"gz":    "application/x-gzip",
	"xz":    "application/x-xz",
	"bz2":   "application/x-bzip2",
	"msi":   "application/x-msi",
	"vmdk":  "application/vmdk",
	"lzh":   "application/lha",
	"wma":   "audio/x-ms-wma",
	"bmp":   "image/bmp",
	"avi":   "video/avi",
	"wav":   "audio/wav",
	"tar":   "application/x-tar",
	"mp3":   "audio/mp3",
	"aac":   "audio/aac",
	"mp4":   "video/mp4",
	"m4a":   "audio/m4a",
	"m4v":   "video/m4v",
	"mov":   "video/quicktime",
	"flv":   "video/x-flv",
	"iso":   "application/x-iso9660-image",
	"dmg":   "application/x-apple-diskimage",
	"html":  "text/html",
	"xml":   "application/xml",
}

var Definitions = []*Definition{
	// This definition according to http://www.garykessler.net/library/file_sigs.html
	{"pic", []*Signature{{HEX: "00"}}}, // mov, pif, sea, ytr
	{"xxx", []*Signature{{HEX: "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"}}},
	{"pdb", []*Signature{{Offset: 11, HEX: "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"}}},
	{"rvt", []*Signature{{HEX: "D0 CF 11 E0 A1 B1 1A E1"}, {Offset: 512, HEX: "00 00 00 00 00 00 00 00"}}},
	{"tbi", []*Signature{{HEX: "00 00 00 00 14 00 00 00"}}},
	{"dat", []*Signature{{Offset: 8, HEX: "00 00 00 00 62 31 05 00 09 00 00 00 00 20 00 00 00 09 00 00 00 00 00 00"}}},
	{"jp2", []*Signature{{HEX: "00 00 00 0C 6A 50 20 20 0D 0A"}}},
	{"3gg", []*Signature{{HEX: "00 00 00 14 66 74 79 70 33 67 70"}}}, // 3gp, 3g2
	{"mp4", []*Signature{{HEX: "00 00 00 14 66 74 79 70 69 73 6F 6D"}}},
	{"mov", []*Signature{{HEX: "00 00 00 14 66 74 79 70 71 74 20 20"}}},
	{"mp4", []*Signature{{HEX: "00 00 00 18 66 74 79 70 33 67 70 35"}}},
	{"m4v", []*Signature{{HEX: "00 00 00 18 66 74 79 70 6D 70 34 32"}}},
	{"mp4", []*Signature{{HEX: "00 00 00 1C 66 74 79 70 4D 53 4E 56 01 29 00 46 4D 53 4E 56 6D 70 34 32"}}},
	{"3gg", []*Signature{{HEX: "00 00 00 20 66 74 79 70 33 67 70"}}}, // 3gp, 3g2
	{"m4a", []*Signature{{HEX: "00 00 00 20 66 74 79 70 4D 34 41 20"}}},
	{"ico", []*Signature{{HEX: "00 00 01 00"}}},  // spl
	{"mpeg", []*Signature{{HEX: "00 00 01 B0"}}}, // mpg
	{"mpeg", []*Signature{{HEX: "00 00 01 B1"}}}, // mpg
	{"mpeg", []*Signature{{HEX: "00 00 01 B2"}}}, // mpg
	{"mpeg", []*Signature{{HEX: "00 00 01 B3"}}}, // mpg
	{"mpeg", []*Signature{{HEX: "00 00 01 B4"}}}, // mpg
	{"mpeg", []*Signature{{HEX: "00 00 01 B5"}}}, // mpg
	{"mpeg", []*Signature{{HEX: "00 00 01 B6"}}}, // mpg
	{"mpeg", []*Signature{{HEX: "00 00 01 B7"}}}, // mpg
	{"mpeg", []*Signature{{HEX: "00 00 01 B8"}}}, // mpg
	{"mpeg", []*Signature{{HEX: "00 00 01 B9"}}}, // mpg
	{"mpeg", []*Signature{{HEX: "00 00 01 BB"}}}, // mpg
	{"mpeg", []*Signature{{HEX: "00 00 01 BC"}}}, // mpg
	{"mpeg", []*Signature{{HEX: "00 00 01 BD"}}}, // mpg
	{"mpeg", []*Signature{{HEX: "00 00 01 BE"}}}, // mpg
	{"mpeg", []*Signature{{HEX: "00 00 01 BF"}}}, // mpg
	{"mpg", []*Signature{{HEX: "00 00 01 BA"}}},  // vob
	{"cur", []*Signature{{HEX: "00 00 02 00"}}},  // wb2
	{"wk1", []*Signature{{HEX: "00 00 02 00 06 04 06 00 08 00 00 00 00 00"}}},
	{"", []*Signature{{HEX: "00 00 03 F3"}}},
	{"wk3", []*Signature{{HEX: "00 00 1A 00 00 10 04 00 00 00 00 00"}}},
	{"wk4", []*Signature{{HEX: "00 00 1A 00 02 10 04 00 00 00 00 00"}}}, // wk5
	{"123", []*Signature{{HEX: "00 00 1A 00 05 10 04"}}},
	{"qxd", []*Signature{{HEX: "00 00 49 49 58 50 52"}}},
	{"qxd", []*Signature{{HEX: "00 00 4D 4D 58 50 52"}}},
	{"", []*Signature{{HEX: "00 00 FE FF"}}},
	{"hlp", []*Signature{{Offset: 6, HEX: "00 00 FF FF FF FF"}}},
	{"ttf", []*Signature{{HEX: "00 01 00 00 00"}}},
	{"mny", []*Signature{{HEX: "00 01 00 00 4D 53 49 53 41 4D 20 44 61 74 61 62 61 73 65"}}},
	{"accdb", []*Signature{{HEX: "00 01 00 00 53 74 61 6E 64 61 72 64 20 41 43 45 20 44 42"}}},
	{"mdb", []*Signature{{HEX: "00 01 00 00 53 74 61 6E 64 61 72 64 20 4A 65 74 20 44 42"}}},
	{"img", []*Signature{{HEX: "00 01 00 08 00 01 00 01 01"}}},
	{"flt", []*Signature{{HEX: "00 01 01"}}},
	{"aba", []*Signature{{HEX: "00 01 42 41"}}},
	{"dba", []*Signature{{HEX: "00 01 42 44"}}},
	{"db", []*Signature{{HEX: "00 06 15 61 00 00 00 02 00 00 04 D2 00 00 10 00"}}},
	{"", []*Signature{{HEX: "00 0D BB A0"}}},
	{"fli", []*Signature{{HEX: "00 11 AF"}}},
	{"", []*Signature{{HEX: "00 14 00 00 01 02"}, {Offset: 8, HEX: "03"}}},
	{"snm", []*Signature{{HEX: "00 1E 84 90 00 00 00 00"}}},
	{"tpl", []*Signature{{HEX: "00 20 AF 30"}}},
	{"enc", []*Signature{{HEX: "00 5C 41 B1 FF"}}},
	{"ppt", []*Signature{{HEX: "D0 CF 11 E0 A1 B1 1A E1"}, {Offset: 512, HEX: "00 6E 1E F0"}}},
	{"sol", []*Signature{{HEX: "00 BF"}}},
	{"mdf", []*Signature{{HEX: "00 FF FF FF FF FF FF FF FF FF FF 00 00 02 00 01"}}},
	{"emf", []*Signature{{HEX: "01 00 00 00"}}},
	{"pic", []*Signature{{HEX: "01 00 00 00 01"}}},
	{"wmf", []*Signature{{HEX: "01 00 09 00 00 03"}}},
	{"arf", []*Signature{{HEX: "01 00 02 00"}}},
	{"fdb", []*Signature{{HEX: "01 00 39 30"}}}, // gdb
	{"tbi", []*Signature{{HEX: "01 01 47 19 A4 00 00 00 00 00 00 00"}}},
	{"mdf", []*Signature{{HEX: "01 0F 00 00"}}},
	{"tr1", []*Signature{{HEX: "01 10"}}},
	{"rgb", []*Signature{{HEX: "01 DA 01 01 00 03"}}},
	{"drw", []*Signature{{HEX: "01 FF 02 04 03 02"}}},
	{"dss", []*Signature{{HEX: "02 64 73 73"}}},
	{"dat", []*Signature{{HEX: "03"}}}, // db3
	{"qph", []*Signature{{HEX: "03 00 00 00"}}},
	{"adx", []*Signature{{HEX: "03 00 00 00 41 50 50 52"}}},
	{"db4", []*Signature{{HEX: "04"}}},
	{"", []*Signature{{HEX: "04 00 00 00"}, {Offset: 12, HEX: "20 03 00 00"}}},
	{"", []*Signature{{HEX: "05 00 00 00"}, {Offset: 12, HEX: "20 03 00 00"}}},
	{"indd", []*Signature{{HEX: "06 06 ED F5 D8 1D 46 E5 BD 31 EF E7 FE 74 B7 1D"}}},
	{"drw", []*Signature{{HEX: "07"}}},
	{"skf", []*Signature{{HEX: "07 53 4B 46"}}},
	{"dtd", []*Signature{{HEX: "07 64 74 32 64 64 74 64"}}},
	//{"db", []*Signature{{HEX: "08"}}}, // obsolete and no longer supported file format.
	{"", []*Signature{{HEX: "08 00 45"}}},
	{"xls", []*Signature{{HEX: "D0 CF 11 E0 A1 B1 1A E1"}, {Offset: 512, HEX: "09 08 10 00 00 06 05 00"}}},
	{"pcx", []*Signature{{HEX: "0A"}, {Offset: 2, HEX: "01 01"}}},
	{"wallet", []*Signature{{HEX: "0A 16 6F 72 67 2E 62 69 74 63 6F 69 6E 2E 70 72"}}},
	{"mp", []*Signature{{HEX: "0C ED"}}},
	{"doc", []*Signature{{HEX: "0D 44 4F 43"}}},
	{"nri", []*Signature{{HEX: "0E 4E 65 72 6F 49 53 4F"}}},
	{"wks", []*Signature{{HEX: "0E 57 4B 53"}}},
	{"ppt", []*Signature{{HEX: "D0 CF 11 E0 A1 B1 1A E1"}, {Offset: 512, HEX: "0F 00 E8 03"}}},
	{"cl5", []*Signature{{HEX: "10 00 00 00"}}},
	{"ntf", []*Signature{{HEX: "1A 00 00"}}},
	{"nsf", []*Signature{{HEX: "1A 00 00 04 00 00"}}},
	{"arc", []*Signature{{HEX: "1A 02"}}},
	{"arc", []*Signature{{HEX: "1A 03"}}},
	{"arc", []*Signature{{HEX: "1A 04"}}},
	{"arc", []*Signature{{HEX: "1A 08"}}},
	{"arc", []*Signature{{HEX: "1A 09"}}},
	{"pak", []*Signature{{HEX: "1A 0B"}}},
	{"eth", []*Signature{{HEX: "1A 35 01 00"}}},
	{"webm", []*Signature{{HEX: "1A 45 DF A3"}}},
	{"mkv", []*Signature{{HEX: "1A 45 DF A3 93 42 82 88 6D 61 74 72 6F 73 6B 61"}}},
	{"dat", []*Signature{{HEX: "1A 52 54 53 20 43 4F 4D 50 52 45 53 53 45 44 20 49 4D 41 47 45 20 56 31 2E 30 1A"}}},
	{"jar", []*Signature{{Offset: 14, HEX: "1A 4A 61 72 1B"}}},
	{"dat", []*Signature{{HEX: "1A 52 54 53 20 43 4F 4D 50 52 45 53 53 45 44 20 49 4D 41 47 45 20 56 31 2E 30 1A"}}},
	{"ws", []*Signature{{HEX: "1D 7D"}}},
	{"gz", []*Signature{{HEX: "1F 8B 08"}}}, // tgz, vlt
	{"tar.z", []*Signature{{HEX: "1F 9D"}}},
	{"tar.z", []*Signature{{HEX: "1F A0"}}},
	{"bsb", []*Signature{{HEX: "21"}}},
	{"ain", []*Signature{{HEX: "21 12"}}},
	{"lib", []*Signature{{HEX: "21 3C 61 72 63 68 3E 0A"}}},
	{"ost", []*Signature{{HEX: "21 42 44 4E"}}}, // pst
	// {"msi", []*Signature{{HEX: "23 20"}}}, // Too wide hit range (e.g. .py)
	{"vmdk", []*Signature{{HEX: "23 20 44 69 73 6B 20 44 65 73 63 72 69 70 74 6F"}}},
	{"dsp", []*Signature{{HEX: "23 20 4D 69 63 72 6F 73 6F 66 74 20 44 65 76 65 6C 6F 70 65 72 20 53 74 75 64 69 6F"}}},
	{"amr", []*Signature{{HEX: "23 21 41 4D 52"}}},
	{"sil", []*Signature{{HEX: "23 21 53 49 4C 4B 0A"}}},
	{"hdr", []*Signature{{HEX: "23 3F 52 41 44 49 41 4E 43 45 0A"}}},
	{"pec", []*Signature{{HEX: "23 50 45 43 30 30 30 31 4C 41 3A"}}},
	{"pes", []*Signature{{HEX: "23 50 45 53 30"}}},
	{"sav", []*Signature{{HEX: "24 46 4C 32 40 28 23 29 20 53 50 53 53 20 44 41 54 41 20 46 49 4C 45"}}},
	{"eps", []*Signature{{HEX: "25 21 50 53 2D 41 64 6F 62 65 2D 33 2E 30 20 45 50 53 46 2D 33 20 30"}}},
	{"pdf", []*Signature{{HEX: "25 50 44 46"}}}, // fdf, ai
	{"fbm", []*Signature{{HEX: "25 62 69 74 6D 61 70"}}},
	{"hqx", []*Signature{{HEX: "28 54 68 69 73 20 66 69 6C 65 20 6D 75 73 74 20 62 65 20 63 6F 6E 76 65 72 74 65 64 20 77 69 74 68 20 42 69 6E 48 65 78 20"}}},
	{"log", []*Signature{{HEX: "2A 2A 2A 20 20 49 6E 73 74 61 6C 6C 61 74 69 6F 2A 2A 2A 20 20 49 6E 73 74 61 6C 6C 61 74 69 6F 6E 20 53 74 61 72 74 65 64 20"}}},
	{"lzh", []*Signature{{Offset: 2, HEX: "2D 6C 68"}}}, // lha
	{"ivr", []*Signature{{HEX: "2E 52 45 43"}}},
	{"rm", []*Signature{{HEX: "2E 52 4D 46"}}}, // rmvb
	{"ra", []*Signature{{HEX: "2E 52 4D 46 00 00 00 12 00"}}},
	{"ra", []*Signature{{HEX: "2E 72 61 FD 00"}}},
	{"au", []*Signature{{HEX: "2E 73 6E 64"}}},
	{"msf", []*Signature{{HEX: "2F 2F 20 3C 21 2D 2D 20 3C 6D 64 62 3A 6D 6F 72 6B 3A 7A"}}},
	{"cat", []*Signature{{HEX: "30"}}},
	{"evt", []*Signature{{HEX: "30 00 00 00 4C 66 4C 65"}}},
	{"wma", []*Signature{{HEX: "30 26 B2 75 8E 66 CF 11 A6 D9 00 AA 00 62 CE 6C"}}},
	{"ntf", []*Signature{{HEX: "30 31 4F 52 44 4E 41 4E 43 45 20 53 55 52 56 45 59 20 20 20 20 20 20 20"}}},
	{"", []*Signature{{HEX: "30 37 30 37 30 31"}}},
	{"", []*Signature{{HEX: "30 37 30 37 30 32"}}},
	{"", []*Signature{{HEX: "30 37 30 37 30 37"}}},
	{"wri", []*Signature{{HEX: "31 BE"}}},
	{"wri", []*Signature{{HEX: "32 BE"}}},
	{"pcs", []*Signature{{HEX: "32 03 10 00 00 00 00 00 00 00 80 00 00 00 FF 00"}}},
	{"", []*Signature{{HEX: "34 CD B2 A1"}}},
	{"7z", []*Signature{{HEX: "37 7A BC AF 27 1C"}}},
	{"", []*Signature{{HEX: "37 E4 53 96 C9 DB D6 07"}}},
	{"psd", []*Signature{{HEX: "38 42 50 53"}}},
	{"sle", []*Signature{{HEX: "3A 56 45 52 53 49 4F 4E"}}},
	// {"asx", []*Signature{{HEX: "3C"}}}, // xdr // Too wide hit range (e.g. .xml)
	// {"dci", []*Signature{{HEX: "3C 21 64 6F 63 74 79 70"}}}, // Too wide hit range
	// {"manifest", []*Signature{{HEX: "3C 3F 78 6D 6C 20 76 65 72 73 69 6F 6E 3D"}}}, // Too wide hit range (e.g. xml)
	// {"xul", []*Signature{{HEX: "3C 3F 78 6D 6C 20 76 65 72 73 69 6F 6E 3D 22 31 2E 30 22 3F 3E"}}}, // Too wide hit range (e.g. xml)
	{"msc", []*Signature{{HEX: "3C 3F 78 6D 6C 20 76 65 72 73 69 6F 6E 3D 22 31 2E 30 22 3F 3E 0D 0A 3C 4D 4D 43 5F 43 6F 6E 73 6F 6C 65 46 69 6C 65 20 43 6F 6E 73 6F 6C 65 56 65 72 73 69 6F 6E 3D 22"}}},
	{"csd", []*Signature{{HEX: "3C 43 73 6F 75 6E 64 53 79 6E 74 68 65 73 69 7A"}}},
	{"mif", []*Signature{{HEX: "3C 4D 61 6B 65 72 46 69 6C 65 20"}}}, // fm
	{"gpx", []*Signature{{HEX: "3C 67 70 78 20 76 65 72 73 69 6F 6E 3D 22 31 2E 31"}}},
	{"b85", []*Signature{{HEX: "3C 7E 36 3C 5C 25 5F 30 67 53 71 68 3B"}}},
	{"wb3", []*Signature{{Offset: 24, HEX: "3E 00 03 00 FE FF 09 00 06"}}},
	{"hlp", []*Signature{{HEX: "3F 5F 03 00"}}}, // gid
	{"enl", []*Signature{{Offset: 32, HEX: "40 40 40 20 00 00 40 40 40 40"}}},
	{"dwg", []*Signature{{HEX: "41 43 31 30"}}},
	{"sle", []*Signature{{HEX: "41 43 76"}}},
	{"", []*Signature{{HEX: "41 43 53 44"}}},
	{"aes", []*Signature{{HEX: "41 45 53"}}},
	{"syw", []*Signature{{HEX: "41 4D 59 4F"}}},
	{"bag", []*Signature{{HEX: "41 4F 4C 20 46 65 65 64 62 61 67"}}},
	{"idx", []*Signature{{HEX: "41 4F 4C 44 42"}}}, // aby
	{"ind", []*Signature{{HEX: "41 4F 4C 49 44 58"}}},
	{"abi", []*Signature{{HEX: "41 4F 4C 49 4E 44 45 58"}}},
	{"org", []*Signature{{HEX: "41 4F 4C 56 4D 31 30 30"}}}, // pfc
	{"dat", []*Signature{{HEX: "41 56 47 36 5F 49 6E 74 65 67 72 69 74 79 5F 44 61 74 61 62 61 73 65"}}},
	{"arc", []*Signature{{HEX: "41 72 43 01"}}},
	{"", []*Signature{{HEX: "42 41 41 44"}}},
	{"vcf", []*Signature{{HEX: "42 45 47 49 4E 3A 56 43 41 52 44 0D 0A"}}},
	{"bli", []*Signature{{HEX: "42 4C 49 32 32 33"}}}, // rbi
	{"bmp", []*Signature{{HEX: "42 4D"}}},             // dib
	{"prc", []*Signature{{HEX: "42 4F 4F 4B 4D 4F 42 49"}}},
	{"bpg", []*Signature{{HEX: "42 50 47 FB"}}},
	{"bz2", []*Signature{{HEX: "42 5A 68"}}}, // tar.bz2, tbz2, tb2
	{"apuf", []*Signature{{HEX: "42 65 67 69 6E 20 50 75 66 66 65 72 20 44 61 74 61 0D 0A"}}},
	{"bli", []*Signature{{HEX: "42 6C 69 6E 6B 20 62 79 20 44 2E 54 2E 53"}}},
	{"rtd", []*Signature{{HEX: "43 23 2B 44 A4 43 4D A5 48 64 72"}}},
	{"iff", []*Signature{{HEX: "43 41 54 20"}}},
	{"cbd", []*Signature{{HEX: "43 42 46 49 4C 45"}}},
	{"iso", []*Signature{{HEX: "43 44 30 30 31"}}},
	{"cso", []*Signature{{HEX: "43 49 53 4F"}}},
	{"db", []*Signature{{HEX: "43 4D 4D 4D 15 00 00 00"}}},
	{"clb", []*Signature{{HEX: "43 4D 58 31"}}},
	{"clb", []*Signature{{HEX: "43 4F 4D 2B"}}},
	{"vmdk", []*Signature{{HEX: "43 4F 57 44"}}},
	{"cpt", []*Signature{{HEX: "43 50 54 37 46 49 4C 45"}}},
	{"cpt", []*Signature{{HEX: "43 50 54 46 49 4C 45"}}},
	{"dat", []*Signature{{HEX: "43 52 45 47"}}},
	{"cru", []*Signature{{HEX: "43 52 55 53 48 20 76"}}},
	{"swf", []*Signature{{HEX: "43 57 53"}}},
	{"cin", []*Signature{{HEX: "43 61 6C 63 75 6C 75 78 20 49 6E 64 6F 6F 72 20"}}},
	{"ctf", []*Signature{{HEX: "43 61 74 61 6C 6F 67 20 33 2E 30 30 00"}}},
	{"dat", []*Signature{{HEX: "43 6C 69 65 6E 74 20 55 72 6C 43 61 63 68 65 20 4D 4D 46 20 56 65 72 20"}}},
	{"voc", []*Signature{{HEX: "43 72 65 61 74 69 76 65 20 56 6F 69 63 65 20 46"}}},
	{"dax", []*Signature{{HEX: "44 41 58 00"}}},
	{"db", []*Signature{{HEX: "44 42 46 48"}}},
	{"dms", []*Signature{{HEX: "44 4D 53 21"}}},
	{"adf", []*Signature{{HEX: "44 4F 53"}}},
	{"dst", []*Signature{{HEX: "44 53 54 62"}}},
	{"dvr", []*Signature{{HEX: "44 56 44"}}}, // ifo
	{"cdr", []*Signature{{HEX: "45 4C 49 54 45 20 43 6F 6D 6D 61 6E 64 65 72 20"}}},
	{"vcd", []*Signature{{HEX: "45 4E 54 52 59 56 43 44 02 00 00 01 02 00 18 58"}}},
	{"dat", []*Signature{{HEX: "45 52 46 53 53 41 56 45 44 41 54 41 46 49 4C 45"}}},
	{"mdi", []*Signature{{HEX: "45 50"}}},
	{"e", []*Signature{{HEX: "45 56 46 09 0D 0A FF 00"}}},
	{"ex", []*Signature{{HEX: "45 56 46 32 0D 0A 81"}}},
	{"evtx", []*Signature{{HEX: "45 6C 66 46 69 6C 65 00"}}},
	{"qbb", []*Signature{{HEX: "45 86 00 00 06 00"}}},
	{"cpe", []*Signature{{HEX: "46 41 58 43 4F 56 45 52 2D 56 45 52"}}},
	{"fdb", []*Signature{{HEX: "46 44 42 48 00"}}},
	{"sbv", []*Signature{{HEX: "46 45 44 46"}}},
	{"", []*Signature{{HEX: "46 49 4C 45"}}},
	{"flv", []*Signature{{HEX: "46 4C 56 01"}}},
	{"iff", []*Signature{{HEX: "46 4F 52 4D"}}},
	{"aiff", []*Signature{{HEX: "46 4F 52 4D 00"}}}, // dax
	{"swf", []*Signature{{HEX: "46 57 53"}}},
	{"eml", []*Signature{{HEX: "46 72 6F 6D 20 20 20"}}},
	{"eml", []*Signature{{HEX: "46 72 6F 6D 20 3F 3F 3F"}}},
	{"eml", []*Signature{{HEX: "46 72 6F 6D 3A 20"}}},
	{"ts", []*Signature{{HEX: "47"}}}, // tsa, tsv
	{"pat", []*Signature{{HEX: "47 46 31 50 41 54 43 48"}}},
	{"gif", []*Signature{{HEX: "47 49 46 38 37 61"}}},
	{"gif", []*Signature{{HEX: "47 49 46 38 39 61"}}},
	{"pat", []*Signature{{HEX: "47 50 41 54"}}},
	{"gx2", []*Signature{{HEX: "47 58 32"}}},
	{"g64", []*Signature{{HEX: "47 65 6E 65 74 65 63 20 4F 6D 6E 69 63 61 73 74"}}},
	{"xpt", []*Signature{{HEX: "48 45 41 44 45 52 20 52 45 43 4F 52 44 2A 2A 2A"}}},
	{"sh3", []*Signature{{HEX: "48 48 47 42 31"}}},
	{"tif", []*Signature{{HEX: "49 20 49"}}}, // tiff
	{"mp3", []*Signature{{HEX: "49 44 33"}}},
	{"koz", []*Signature{{HEX: "49 44 33 03 00 00 00"}}},
	{"crw", []*Signature{{HEX: "49 49 1A 00 00 00 48 45 41 50 43 43 44 52 02 00"}}},
	{"tif", []*Signature{{HEX: "49 49 2A 00"}}}, // tiff
	{"cr2", []*Signature{{HEX: "49 49 2A 00 10 00 00 00 43 52"}}},
	{"db", []*Signature{{HEX: "49 4D 4D 4D 15 00 00 00"}}},
	{"cab", []*Signature{{HEX: "49 53 63 28"}}}, // hdr
	{"lit", []*Signature{{HEX: "49 54 4F 4C 49 54 4C 53"}}},
	{"chi", []*Signature{{HEX: "49 54 53 46"}}}, // chm
	{"dat", []*Signature{{HEX: "49 6E 6E 6F 20 53 65 74 75 70 20 55 6E 69 6E 73 74 61 6C 6C 20 4C 6F 67 20 28 62 29"}}},
	{"ipd", []*Signature{{HEX: "49 6E 74 65 72 40 63 74 69 76 65 20 50 61 67 65"}}},
	{"jar", []*Signature{{HEX: "4A 41 52 43 53 00"}}},
	{"art", []*Signature{{HEX: "4A 47 03 0E"}}},
	{"art", []*Signature{{HEX: "4A 47 04 0E"}}},
	{"vmdk", []*Signature{{HEX: "4B 44 4D"}}},
	{"vmdk", []*Signature{{HEX: "4B 44 4D 56"}}},
	{"kgb", []*Signature{{HEX: "4B 47 42 5F 61 72 63 68 20 2D"}}},
	{"shd", []*Signature{{HEX: "4B 49 00 00"}}},
	{"", []*Signature{{HEX: "4B 57 41 4A 88 F0 27 D1"}}},
	{"lnk", []*Signature{{HEX: "4C 00 00 00 01 14 02 00"}}},
	{"obj", []*Signature{{HEX: "4C 01"}}},
	{"dst", []*Signature{{HEX: "4C 41 3A"}}},
	{"iff", []*Signature{{HEX: "4C 49 53 54"}}},
	{"hlp", []*Signature{{HEX: "4C 4E 02 00"}}}, // gid
	{"e", []*Signature{{HEX: "4C 56 46 09 0D 0A FF 00"}}},
	{"pdb", []*Signature{{HEX: "4D 2D 57 20 50 6F 63 6B 65 74 20 44 69 63 74 69"}}},
	{"mar", []*Signature{{HEX: "4D 41 52 31 00"}}},
	{"mar", []*Signature{{HEX: "4D 41 52 43"}}},
	{"mar", []*Signature{{HEX: "4D 41 72 30 00"}}},
	{"mte", []*Signature{{HEX: "4D 43 57 20 54 65 63 68 6E 6F 67 6F 6C 69 65 73"}}},
	{"hdmp", []*Signature{{HEX: "4D 44 4D 50 93 A7"}}}, // dmp
	{"mls", []*Signature{{HEX: "4D 49 4C 45 53"}}},
	{"mls", []*Signature{{HEX: "4D 4C 53 57"}}},
	{"tif", []*Signature{{HEX: "4D 4D 00 2A"}}}, // tiff
	{"tif", []*Signature{{HEX: "4D 4D 00 2B"}}}, // tiff
	{"mmf", []*Signature{{HEX: "4D 4D 4D 44 00 00"}}},
	{"nvram", []*Signature{{HEX: "4D 52 56 4E"}}},
	{"cab", []*Signature{{HEX: "4D 53 43 46"}}}, // ppz, snp
	{"tlb", []*Signature{{HEX: "4D 53 46 54 02 00 01 00"}}},
	{"wim", []*Signature{{HEX: "4D 53 57 49 4D"}}},
	{"cdr", []*Signature{{HEX: "4D 53 5F 56 4F 49 43 45"}}}, // dvf, msv
	{"mid", []*Signature{{HEX: "4D 54 68 64"}}},             // mid, midi, pcs
	{"dsn", []*Signature{{HEX: "4D 56"}}},
	{"mls", []*Signature{{HEX: "4D 56 32 31 34"}}},
	{"mls", []*Signature{{HEX: "4D 56 32 43"}}},
	{"exe", []*Signature{{HEX: "4D 5A"}}},                   // com, dll, drv, exe, pif, qts, qtx, sys, acm, ax, cpl, fon, ocx, olb, scr, vbx, vxd, 386
	{"api", []*Signature{{HEX: "4D 5A 90 00 03 00 00 00"}}}, // ax, flt
	{"zap", []*Signature{{HEX: "4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF"}}},
	{"pdb", []*Signature{{HEX: "4D 69 63 72 6F 73 6F 66 74 20 43 2F 43 2B 2B 20"}}},
	{"sln", []*Signature{{HEX: "4D 69 63 72 6F 73 6F 66 74 20 56 69 73 75 61 6C 20 53 74 75 64 69 6F 20 53 6F 6C 75 74 69 6F 6E 20 46 69 6C 65"}}},
	{"wpl", []*Signature{{Offset: 84, HEX: "4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 4D 65 64 69 61 20 50 6C 61 79 65 72 20 2D 2D 20"}}},
	{"gdb", []*Signature{{HEX: "4D 73 52 63 66"}}},
	{"dat", []*Signature{{HEX: "4E 41 56 54 52 41 46 46 49 43"}}},
	{"jnt", []*Signature{{HEX: "4E 42 2A 00"}}}, // jtp
	{"nsf", []*Signature{{HEX: "4E 45 53 4D 1A 01"}}},
	{"ntf", []*Signature{{HEX: "4E 49 54 46 30"}}},
	{"cod", []*Signature{{HEX: "4E 61 6D 65 3A 20"}}},
	{"attachment", []*Signature{{HEX: "4F 50 43 4C 44 41 54"}}},
	{"dbf", []*Signature{{HEX: "4F 50 4C 44 61 74 61 62 61 73 65 46 69 6C 65"}}},
	{"oga", []*Signature{{HEX: "4F 67 67 53 00 02 00 00 00 00 00 00 00 00"}}}, // ogg, ogv, ogx
	{"dw4", []*Signature{{HEX: "4F 7B"}}},
	{"idx", []*Signature{{HEX: "50 00 00 00 20 00 00 00"}}},
	{"pgm", []*Signature{{HEX: "50 35 0A"}}},
	{"pak", []*Signature{{HEX: "50 41 43 4B"}}},
	{"dmp", []*Signature{{HEX: "50 41 47 45 44 55 36 34"}}},
	{"dmp", []*Signature{{HEX: "50 41 47 45 44 55 4D 50"}}},
	{"pax", []*Signature{{HEX: "50 41 58"}}},
	{"dat", []*Signature{{HEX: "50 45 53 54"}}},
	{"pgd", []*Signature{{HEX: "50 47 50 64 4D 41 49 4E"}}},
	{"img", []*Signature{{HEX: "50 49 43 54 00 08"}}},
	{"zip", []*Signature{{HEX: "50 4B 03 04"}}}, // jar, kmz, kwd, odt, odp, ott, sxc, sxd, sxi, sxw, wmz, xpi, xps, xpt
	{"epub", []*Signature{{HEX: "50 4B 03 04 0A 00 02 00"}}},
	{"zip", []*Signature{{HEX: "50 4B 03 04 14 00 01 00 63 00 00 00 00 00"}}},
	// {"docx", []*Signature{{HEX: "50 4B 03 04 14 00 06 00"}}}, // docx, xlsx, pptx
	{"jar", []*Signature{{HEX: "50 4B 03 04 14 00 08 00 08 00"}}},
	{"zip", []*Signature{{HEX: "50 4B 05 06"}}},
	{"zip", []*Signature{{HEX: "50 4B 07 08"}}},
	{"zip", []*Signature{{Offset: 30, HEX: "50 4B 4C 49 54 45"}}},
	{"zip", []*Signature{{Offset: 526, HEX: "50 4B 53 70 58"}}},
	{"grp", []*Signature{{HEX: "50 4D 43 43"}}},
	{"dat", []*Signature{{HEX: "50 4E 43 49 55 4E 44 4F"}}},
	{"dat", []*Signature{{HEX: "50 4D 4F 43 43 4D 4F 43"}}},
	{"puf", []*Signature{{HEX: "50 55 46 58"}}},
	{"qel", []*Signature{{Offset: 92, HEX: "51 45 4C 20"}}},
	{"img", []*Signature{{HEX: "51 46 49 FB"}}},
	{"abd", []*Signature{{HEX: "51 57 20 56 65 72 2E 20"}}}, // qsd
	{"msg", []*Signature{{HEX: "D0 CF 11 E0 A1 B1 1A E1"}, {Offset: 512, HEX: "52 00 6F 00 6F 00 74 00 20 00 45 00 6E 00 74 00 72 00 79 00"}}},
	{"dat", []*Signature{{HEX: "52 41 5A 41 54 44 42 31"}}},
	{"reg", []*Signature{{HEX: "52 45 47 45 44 49 54"}}}, // sud
	{"adf", []*Signature{{HEX: "52 45 56 4E 55 4D 3A 2C"}}},
	{"ani", []*Signature{{HEX: "52 49 46 46"}}}, // cmx, cdr, dat, ds4, 4xm
	{"avi", []*Signature{{HEX: "52 49 46 46"}, {Offset: 8, HEX: "41 56 49 20 4C 49 53 54"}}},
	{"cda", []*Signature{{HEX: "52 49 46 46"}, {Offset: 8, HEX: "43 44 44 41 66 6D 74 20"}}},
	{"qcp", []*Signature{{HEX: "52 49 46 46"}, {Offset: 8, HEX: "51 4C 43 4D 66 6D 74 20"}}},
	{"rmi", []*Signature{{HEX: "52 49 46 46"}, {Offset: 8, HEX: "52 4D 49 44 64 61 74 61"}}},
	{"wav", []*Signature{{HEX: "52 49 46 46"}, {Offset: 8, HEX: "57 41 56 45 66 6D 74 20"}}},
	{"webp", []*Signature{{HEX: "52 49 46 46"}, {Offset: 8, HEX: "57 45 42 50"}}},
	{"cap", []*Signature{{HEX: "52 54 53 53"}}},
	{"rar", []*Signature{{HEX: "52 61 72 21 1A 07 00"}}},
	{"rar", []*Signature{{HEX: "52 61 72 21 1A 07 01 00"}}},
	{"eml", []*Signature{{HEX: "52 65 74 75 72 6E 2D 50 61 74 68 3A 20"}}},
	{"pf", []*Signature{{Offset: 4, HEX: "53 43 43 41"}}},
	{"ast", []*Signature{{HEX: "53 43 48 6C"}}},
	{"img", []*Signature{{HEX: "53 43 4D 49"}}},
	{"dpx", []*Signature{{HEX: "53 44 50 58"}}},
	{"shw", []*Signature{{HEX: "53 48 4F 57"}}},
	{"cpi", []*Signature{{HEX: "53 49 45 54 52 4F 4E 49 43 53 20 58 52 44 20 53 43 53 20 58 52 44 20 53 43 41 4E"}}},
	{"fits", []*Signature{{HEX: "53 49 4D 50 4C 45 20 20 3D 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 54"}}},
	{"sit", []*Signature{{HEX: "53 49 54 21 00"}}},
	{"sdr", []*Signature{{HEX: "53 4D 41 52 54 44 52 57"}}},
	{"spf", []*Signature{{HEX: "53 50 46 49 00"}}},
	{"spvchain", []*Signature{{HEX: "53 50 56 42"}}},
	{"cnv", []*Signature{{HEX: "53 51 4C 4F 43 4F 4E 56 48 44 00 00 31 2E 30 00"}}},
	{"db", []*Signature{{HEX: "53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33 00"}}},
	{"", []*Signature{{HEX: "53 5A 20 88 F0 27 33 D1"}}},
	{"", []*Signature{{HEX: "53 5A 44 44 88 F0 27 33"}}},
	{"sym", []*Signature{{HEX: "53 6D 62 6C"}}},
	{"sit", []*Signature{{HEX: "53 74 75 66 66 49 74 20 28 63 29 31 39 39 37 2D"}}},
	{"cal", []*Signature{{HEX: "53 75 70 65 72 43 61 6C 63"}}},
	{"thp", []*Signature{{HEX: "54 48 50 00"}}},
	{"info", []*Signature{{HEX: "54 68 69 73 20 69 73 20"}}},
	{"uce", []*Signature{{HEX: "55 43 45 58"}}},
	{"ufa", []*Signature{{HEX: "55 46 41 C6 D2 C1"}}},
	{"dat", []*Signature{{HEX: "55 46 4F 4F 72 62 69 74"}}},
	{"pch", []*Signature{{HEX: "56 43 50 43 48 30"}}},
	{"ctl", []*Signature{{HEX: "56 45 52 53 49 4F 4E 20"}}},
	{"mif", []*Signature{{HEX: "56 65 72 73 69 6F 6E 20"}}},
	{"dat", []*Signature{{HEX: "57 4D 4D 50"}}},
	{"ws2", []*Signature{{HEX: "57 53 32 30 30 30"}}},
	{"zip", []*Signature{{Offset: 29152, HEX: "57 69 6E 5A 69 70"}}},
	{"lwp", []*Signature{{HEX: "57 6F 72 64 50 72 6F"}}},
	{"eml", []*Signature{{HEX: "58 2D"}}},
	{"cap", []*Signature{{HEX: "58 43 50 00"}}},
	{"xpt", []*Signature{{HEX: "58 50 43 4F 4D 0A 54 79 70 65 4C 69 62"}}},
	{"dpx", []*Signature{{HEX: "58 50 44 53"}}},
	{"bdr", []*Signature{{HEX: "58 54"}}},
	{"zoo", []*Signature{{HEX: "5A 4F 4F 20"}}},
	{"swf", []*Signature{{HEX: "5A 57 53"}}},
	{"ecf", []*Signature{{HEX: "5B 47 65 6E 65 72 61 6C 5D 0D 0A 44 69 73 70 6C 61 79 20 4E 61 6D 65 3D 3C 44 69 73 70 6C 61 79 4E 61 6D 65"}}},
	{"vcw", []*Signature{{HEX: "5B 4D 53 56 43"}}},
	{"dun", []*Signature{{HEX: "5B 50 68 6F 6E 65 5D"}}},
	{"sam", []*Signature{{HEX: "5B 56 45 52 5D"}}},
	{"sam", []*Signature{{HEX: "5B 76 65 72 5D"}}},
	{"vmd", []*Signature{{HEX: "5B 56 4D 44 5D"}}},
	{"vmd", []*Signature{{HEX: "5B 76 6D 64 5D"}}},
	{"cif", []*Signature{{Offset: 2, HEX: "5B 56 65 72 73 69 6F 6E"}}},
	{"cpx", []*Signature{{HEX: "5B 57 69 6E 64 6F 77 73 20 4C 61 74 69 6E 20"}}},
	{"cfg", []*Signature{{HEX: "5B 66 6C 74 73 69 6D 2E 30 5D"}}},
	{"pls", []*Signature{{HEX: "5B 70 6C 61 79 6C 69 73 74 5D"}}},
	{"hus", []*Signature{{HEX: "5D FC C8 00"}}},
	{"jar", []*Signature{{HEX: "5F 27 A8 89"}}},
	{"cas", []*Signature{{HEX: "5F 43 41 53 45 5F"}}}, // cbk
	{"arj", []*Signature{{HEX: "60 EA"}}},
	{"", []*Signature{{HEX: "62 65 67 69 6E"}}},
	{"b64", []*Signature{{HEX: "62 65 67 69 6E 2D 62 61 73 65 36 34"}}},
	{"plist", []*Signature{{HEX: "62 70 6C 69 73 74"}}},
	{"caf", []*Signature{{HEX: "63 61 66 66"}}},
	{"vhd", []*Signature{{HEX: "63 6F 6E 65 63 74 69 78"}}},
	{"csh", []*Signature{{HEX: "63 75 73 68 00 00 00 02 00 00 00"}}},
	{"p10", []*Signature{{HEX: "64 00 00 00"}}},
	{"dex", []*Signature{{HEX: "64 65 78 0A"}}},
	{"au", []*Signature{{HEX: "64 6E 73 2E"}}},
	{"dsw", []*Signature{{HEX: "64 73 77 66 69 6C 65"}}},
	{"shd", []*Signature{{HEX: "66 49 00 00"}}},
	{"flac", []*Signature{{HEX: "66 4C 61 43 00 00 00 22"}}},
	{"mp4", []*Signature{{Offset: 4, HEX: "66 74 79 70 33 67 70 35"}}},
	{"m4a", []*Signature{{Offset: 4, HEX: "66 74 79 70 4D 34 41 20"}}},
	{"mp4", []*Signature{{Offset: 4, HEX: "66 74 79 70 4D 53 4E 56"}}},
	{"mp4", []*Signature{{Offset: 4, HEX: "66 74 79 70 69 73 6F 6D"}}},
	{"m4v", []*Signature{{Offset: 4, HEX: "66 74 79 70 6D 70 34 32"}}},
	{"mov", []*Signature{{Offset: 4, HEX: "66 74 79 70 71 74 20 20"}}},
	{"shd", []*Signature{{HEX: "67 49 00 00"}}},
	{"xcf", []*Signature{{HEX: "67 69 6d 70 20 78 63 66 20"}}},
	{"shd", []*Signature{{HEX: "68 49 00 00"}}},
	{"dbb", []*Signature{{HEX: "6C 33 33 6C"}}},
	{"mov", []*Signature{{Offset: 4, HEX: "6D 6F 6F 76"}}},
	{"tpl", []*Signature{{HEX: "6D 73 46 69 6C 74 65 72 4C 69 73 74"}}},
	{"info", []*Signature{{HEX: "6D 75 6C 74 69 42 69 74 2E 69 6E 66 6F"}}},
	{"", []*Signature{{HEX: "6F 3C"}}},
	{"", []*Signature{{HEX: "6F 70 64 61 74 61 30 31"}}},
	{"dat", []*Signature{{HEX: "72 65 67 66"}}},
	{"acd", []*Signature{{HEX: "72 69 66 66"}}},
	{"ram", []*Signature{{HEX: "72 74 73 70 3A 2F 2F"}}},
	{"dat", []*Signature{{HEX: "73 6C 68 21"}}},
	{"dat", []*Signature{{HEX: "73 6C 68 2E"}}},
	{"pdb", []*Signature{{HEX: "73 6D 5F"}}},
	{"stl", []*Signature{{HEX: "73 6F 6C 69 64"}}},
	{"cal", []*Signature{{HEX: "73 72 63 64 6F 63 69 64 3A"}}},
	{"pdb", []*Signature{{HEX: "73 7A 65 7A"}}},
	{"prc", []*Signature{{Offset: 60, HEX: "74 42 4D 50 4B 6E 57 72"}}},
	{"tar", []*Signature{{Offset: 257, HEX: "75 73 74 61 72"}}},
	{"exr", []*Signature{{HEX: "76 2F 31 01"}}},
	{"flt", []*Signature{{HEX: "76 32 30 30 33 2E 31 30 0D 0A 30 0D 0A"}}},
	{"dmg", []*Signature{{HEX: "78 01 73 0D 62 62 60"}}},
	{"xar", []*Signature{{HEX: "78 61 72 21"}}},
	{"info", []*Signature{{HEX: "7A 62 65 78"}}},
	{"lgc", []*Signature{{HEX: "7B 0D 0A 6F 20"}}}, // lgd
	{"pwi", []*Signature{{HEX: "7B 5C 70 77 69"}}},
	{"rtf", []*Signature{{HEX: "7B 5C 72 74 66 31"}}},
	{"csd", []*Signature{{HEX: "7C 4B C3 74 E1 C8 53 A4 79 B9 01 1D FC 4F DD 13"}}},
	{"psp", []*Signature{{HEX: "7E 42 4B 00"}}},
	{"img", []*Signature{{HEX: "7E 74 2C 01 50 70 02 4D 52 01 00 00 00 08 00 00 00 01 00 00 31 00 00 00 31 00 00 00 43 01 FF 00 01 00 08 00 01 00 00 00 7e 74 2c 01"}}},
	{"", []*Signature{{HEX: "7F 45 4C 46"}}},
	{"obj", []*Signature{{HEX: "80"}}},
	{"adx", []*Signature{{HEX: "80 00 00 20 03 12 04"}}},
	{"cin", []*Signature{{HEX: "80 2A 5F D7"}}},
	{"wab", []*Signature{{HEX: "81 32 84 C1 85 05 D0 11 B2 90 00 AA 00 3C F6 76"}}},
	{"wpf", []*Signature{{HEX: "81 CD AB"}}},
	{"", []*Signature{{HEX: "86 DD 61"}}},
	{"", []*Signature{{HEX: "86 DD 62"}}},
	{"", []*Signature{{HEX: "86 DD 63"}}},
	{"", []*Signature{{HEX: "86 DD 64"}}},
	{"", []*Signature{{HEX: "86 DD 65"}}},
	{"", []*Signature{{HEX: "86 DD 66"}}},
	{"", []*Signature{{HEX: "86 DD 67"}}},
	{"", []*Signature{{HEX: "86 DD 68"}}},
	{"", []*Signature{{HEX: "86 DD 69"}}},
	{"", []*Signature{{HEX: "86 DD 6A"}}},
	{"", []*Signature{{HEX: "86 DD 6B"}}},
	{"", []*Signature{{HEX: "86 DD 6C"}}},
	{"", []*Signature{{HEX: "86 DD 6D"}}},
	{"", []*Signature{{HEX: "86 DD 6E"}}},
	{"", []*Signature{{HEX: "86 DD 6F"}}},
	{"", []*Signature{{HEX: "86 DD 70"}}},
	{"", []*Signature{{HEX: "86 DD 71"}}},
	{"", []*Signature{{HEX: "86 DD 72"}}},
	{"", []*Signature{{HEX: "86 DD 73"}}},
	{"", []*Signature{{HEX: "86 DD 74"}}},
	{"", []*Signature{{HEX: "86 DD 75"}}},
	{"", []*Signature{{HEX: "86 DD 76"}}},
	{"", []*Signature{{HEX: "86 DD 77"}}},
	{"", []*Signature{{HEX: "86 DD 78"}}},
	{"", []*Signature{{HEX: "86 DD 79"}}},
	{"", []*Signature{{HEX: "86 DD 7A"}}},
	{"png", []*Signature{{HEX: "89 50 4E 47 0D 0A 1A 0A"}}},
	{"aw", []*Signature{{HEX: "8A 01 09 00 00 00 E1 08 00 00 99 19"}}},
	{"hap", []*Signature{{HEX: "91 33 48 46"}}},
	{"skr", []*Signature{{HEX: "95 00"}}},
	{"skr", []*Signature{{HEX: "95 01"}}},
	{"jb2", []*Signature{{HEX: "97 4A 42 32 0D 0A 1A 0A"}}},
	{"gpg", []*Signature{{HEX: "99"}}},
	{"pkr", []*Signature{{HEX: "99 01"}}},
	{"wab", []*Signature{{HEX: "9C CB CB 8D 13 75 D2 11 91 58 00 C0 4F 79 56 A4"}}},
	{"ppt", []*Signature{{HEX: "D0 CF 11 E0 A1 B1 1A E1"}, {Offset: 512, HEX: "A0 46 1D F0"}}},
	{"", []*Signature{{HEX: "A1 B2 C3 D4"}}},
	{"", []*Signature{{HEX: "A1 B2 CD 34"}}},
	{"dat", []*Signature{{HEX: "A9 0D 00 00 00 00 00 00"}}},
	{"qdf", []*Signature{{HEX: "AC 9E BD 8F 00 00"}}},
	{"", []*Signature{{HEX: "AC ED"}}},
	{"pdb", []*Signature{{HEX: "AC ED 00 05 73 72 00 12 62 67 62 6C 69 74 7A 2E"}}},
	{"pwl", []*Signature{{HEX: "B0 4D 46 43"}}},
	{"dcx", []*Signature{{HEX: "B1 68 DE 3A"}}},
	{"tib", []*Signature{{HEX: "B4 6E 68 44"}}},
	{"cal", []*Signature{{HEX: "B5 A2 B0 B3 B3 B0 A5 B5"}}},
	{"wri", []*Signature{{HEX: "BE 00 00 00 AB 00 00 00 00 00 00 00 00"}}},
	{"dat", []*Signature{{HEX: "BE BA FE CA 0F 50 61 6C 6D 53 47 20 44 61 74 61"}}},
	{"acs", []*Signature{{HEX: "C3 AB CD AB"}}},
	{"eps", []*Signature{{HEX: "C5 D0 D3 C6"}}},
	{"lbk", []*Signature{{HEX: "C8 00 79 00"}}},
	{"class", []*Signature{{HEX: "CA FE BA BE"}}},
	{"jar", []*Signature{{HEX: "CA FE D0 0D"}}}, // https://en.wikipedia.org/wiki/Magic_number_(programming)
	{"", []*Signature{{HEX: "CD 20 AA AA 02 00 00 00"}}},
	{"jceks", []*Signature{{HEX: "CE CE CE CE"}}},
	{"", []*Signature{{HEX: "CE FA ED FE"}}},
	{"doc", []*Signature{{HEX: "CF 11 E0 A1 B1 1A E1 00"}}},
	{"dbx", []*Signature{{HEX: "CF AD 12 FE"}}},
	{"", []*Signature{{HEX: "CF FA ED FE"}}},
	{"msi", []*Signature{{HEX: "D0 CF 11 E0 A1 B1 1A E1"}}}, // doc, dot, pps, ppt, xla, xls, wiz, ac, adp, apr, db, msc, msg, msi, mtw, opt, pub, qbm, rvt, sou, spo, vsd, wps
	{"ftr", []*Signature{{HEX: "D2 0A 00 00"}}},
	{"arl", []*Signature{{HEX: "D4 2A"}}}, // aut
	{"", []*Signature{{HEX: "D4 C3 B2 A1"}}},
	{"wmf", []*Signature{{HEX: "D7 CD C6 9A"}}},
	{"doc", []*Signature{{HEX: "DB A5 2D 00"}}},
	{"cpl", []*Signature{{HEX: "DC DC"}}},
	{"efx", []*Signature{{HEX: "DC FE"}}},
	{"info", []*Signature{{HEX: "E3 10 00 01 00 00 00 00"}}},
	{"pwl", []*Signature{{HEX: "E3 82 85 96"}}},
	{"one", []*Signature{{HEX: "E4 52 5C 7B 8C D8 A7 4D AE B1 53 78 D0 29 96 D3"}}},
	{"com", []*Signature{{HEX: "E8"}}}, // sys
	{"com", []*Signature{{HEX: "E9"}}}, // sys
	{"com", []*Signature{{HEX: "EB"}}}, // sys
	{"img", []*Signature{{HEX: "EB 3C 90 2A"}}},
	{"", []*Signature{{HEX: "EB 52 90 2D 46 56 45 2D 46 53 2D"}}},
	{"", []*Signature{{HEX: "EB 58 90 2D 46 56 45 2D 46 53 2D"}}},
	{"doc", []*Signature{{HEX: "D0 CF 11 E0 A1 B1 1A E1"}, {Offset: 512, HEX: "EC A5 C1 00"}}},
	{"rpm", []*Signature{{HEX: "ED AB EE DB"}}},
	{"", []*Signature{{HEX: "EF BB BF"}}},
	{"dat", []*Signature{{HEX: "F9 BE B4 D9"}}},
	{"xz", []*Signature{{HEX: "FD 37 7A 58 5A 00"}}},
	{"pub", []*Signature{{HEX: "D0 CF 11 E0 A1 B1 1A E1"}, {Offset: 512, HEX: "FD FF FF FF 02"}}},
	{"qbm", []*Signature{{HEX: "D0 CF 11 E0 A1 B1 1A E1"}, {Offset: 512, HEX: "FD FF FF FF 04"}}}, // suo
	{"ppt", []*Signature{{HEX: "D0 CF 11 E0 A1 B1 1A E1"}, {Offset: 512, HEX: "FD FF FF FF"}, {Offset: 518, HEX: "00 00"}}},
	{"xls", []*Signature{{HEX: "D0 CF 11 E0 A1 B1 1A E1"}, {Offset: 512, HEX: "FD FF FF FF"}, {Offset: 517, HEX: "00"}}},
	{"xls", []*Signature{{HEX: "D0 CF 11 E0 A1 B1 1A E1"}, {Offset: 512, HEX: "FD FF FF FF"}, {Offset: 517, HEX: "02"}}},
	{"xls", []*Signature{{HEX: "D0 CF 11 E0 A1 B1 1A E1"}, {Offset: 512, HEX: "FD FF FF FF 20 00 00 00"}}}, // opt
	{"db", []*Signature{{HEX: "D0 CF 11 E0 A1 B1 1A E1"}, {Offset: 512, HEX: "FD FF FF FF"}, {Offset: 524, HEX: "04 00 00 00"}}},
	{"", []*Signature{{HEX: "FE ED FA CE"}}},
	{"", []*Signature{{HEX: "FE ED FA CF"}}},
	{"jks", []*Signature{{HEX: "FE ED FE ED"}}},
	{"gho", []*Signature{{HEX: "FE EF"}}}, // ghs
	{"", []*Signature{{HEX: "FE FF"}}},
	{"sys", []*Signature{{HEX: "FF"}}},
	{"wks", []*Signature{{HEX: "FF 00 02 00 04 04 05 54 02 00"}}},
	{"qrp", []*Signature{{HEX: "FF 0A 00"}}},
	{"cpi", []*Signature{{HEX: "FF 46 4F 4E 54"}}},
	{"sys", []*Signature{{HEX: "FF 4B 45 59 42 20 20 20"}}},
	{"wp", []*Signature{{HEX: "FF 57 50 43"}}}, // wpd, wpg, wpp, wp5, wp6
	{"jpg", []*Signature{{HEX: "FF D8 FF"}}},   // NOTES on JPEG file headers: It appears that one can safely say that all JPEG files start with the three hex digits 0xFF-D8-FF.
	{"mp3", []*Signature{{HEX: "FF E0"}}},      // mpeg, mpg, mp3
	{"mp3", []*Signature{{HEX: "FF E1"}}},      // mpeg, mpg, mp3
	{"mp3", []*Signature{{HEX: "FF E2"}}},      // mpeg, mpg, mp3
	{"mp3", []*Signature{{HEX: "FF E3"}}},      // mpeg, mpg, mp3
	{"mp3", []*Signature{{HEX: "FF E4"}}},      // mpeg, mpg, mp3
	{"mp3", []*Signature{{HEX: "FF E5"}}},      // mpeg, mpg, mp3
	{"mp3", []*Signature{{HEX: "FF E6"}}},      // mpeg, mpg, mp3
	{"mp3", []*Signature{{HEX: "FF E7"}}},      // mpeg, mpg, mp3
	{"mp3", []*Signature{{HEX: "FF E8"}}},      // mpeg, mpg, mp3
	{"mp3", []*Signature{{HEX: "FF E9"}}},      // mpeg, mpg, mp3
	{"mp3", []*Signature{{HEX: "FF EA"}}},      // mpeg, mpg, mp3
	{"mp3", []*Signature{{HEX: "FF EB"}}},      // mpeg, mpg, mp3
	{"mp3", []*Signature{{HEX: "FF EC"}}},      // mpeg, mpg, mp3
	{"mp3", []*Signature{{HEX: "FF ED"}}},      // mpeg, mpg, mp3
	{"mp3", []*Signature{{HEX: "FF EE"}}},      // mpeg, mpg, mp3
	{"mp3", []*Signature{{HEX: "FF EF"}}},      // mpeg, mpg, mp3
	{"mp3", []*Signature{{HEX: "FF F0"}}},      // mpeg, mpg, mp3
	{"aac", []*Signature{{HEX: "FF F1"}}},
	{"mp3", []*Signature{{HEX: "FF F2"}}}, // mpeg, mpg, mp3
	{"mp3", []*Signature{{HEX: "FF F3"}}}, // mpeg, mpg, mp3
	{"mp3", []*Signature{{HEX: "FF F4"}}}, // mpeg, mpg, mp3
	{"mp3", []*Signature{{HEX: "FF F5"}}}, // mpeg, mpg, mp3
	{"mp3", []*Signature{{HEX: "FF F6"}}}, // mpeg, mpg, mp3
	{"mp3", []*Signature{{HEX: "FF F7"}}}, // mpeg, mpg, mp3
	{"mp3", []*Signature{{HEX: "FF F8"}}}, // mpeg, mpg, mp3
	{"aac", []*Signature{{HEX: "FF F9"}}},
	{"mp3", []*Signature{{HEX: "FF FA"}}}, // mpeg, mpg, mp3
	{"mp3", []*Signature{{HEX: "FF FB"}}}, // mpeg, mpg, mp3
	{"mp3", []*Signature{{HEX: "FF FC"}}}, // mpeg, mpg, mp3
	{"mp3", []*Signature{{HEX: "FF FD"}}}, // mpeg, mpg, mp3
	{"reg", []*Signature{{HEX: "FF FE"}}},
	{"mp3", []*Signature{{HEX: "FF FF"}}}, // mpeg, mpg, mp3
	{"", []*Signature{{HEX: "FF FE 00 00"}}},
	{"mof", []*Signature{{HEX: "FF FE 23 00 6C 00 69 00 6E 00 65 00 20 00 31 00"}}},
	{"sys", []*Signature{{HEX: "FF FF FF FF"}}},
}

var DefinitionsForText = []*Definition{
	// This definition according to https://golang.org/pkg/net/http/#DetectContentType
	{"html", []*Signature{{String: "<!DOCTYPE HTML "}}},
	{"html", []*Signature{{String: "<HTML "}}},
	{"html", []*Signature{{String: "<HEAD "}}},
	{"html", []*Signature{{String: "<SCRIPT "}}},
	{"html", []*Signature{{String: "<IFRAME "}}},
	{"html", []*Signature{{String: "<H1 "}}},
	{"html", []*Signature{{String: "<DIV "}}},
	{"html", []*Signature{{String: "<FONT "}}},
	{"html", []*Signature{{String: "<TABLE "}}},
	{"html", []*Signature{{String: "<A "}}},
	{"html", []*Signature{{String: "<STYLE "}}},
	{"html", []*Signature{{String: "<TITLE "}}},
	{"html", []*Signature{{String: "<B "}}},
	{"html", []*Signature{{String: "<BODY "}}},
	{"html", []*Signature{{String: "<BR "}}},
	{"html", []*Signature{{String: "<P "}}},
	{"html", []*Signature{{String: "<!-- "}}},
	{"html", []*Signature{{String: "<!DOCTYPE HTML>"}}},
	{"html", []*Signature{{String: "<HTML>"}}},
	{"html", []*Signature{{String: "<HEAD>"}}},
	{"html", []*Signature{{String: "<SCRIPT>"}}},
	{"html", []*Signature{{String: "<IFRAME>"}}},
	{"html", []*Signature{{String: "<H1>"}}},
	{"html", []*Signature{{String: "<DIV>"}}},
	{"html", []*Signature{{String: "<FONT>"}}},
	{"html", []*Signature{{String: "<TABLE>"}}},
	{"html", []*Signature{{String: "<A>"}}},
	{"html", []*Signature{{String: "<STYLE>"}}},
	{"html", []*Signature{{String: "<TITLE>"}}},
	{"html", []*Signature{{String: "<B>"}}},
	{"html", []*Signature{{String: "<BODY>"}}},
	{"html", []*Signature{{String: "<BR>"}}},
	{"html", []*Signature{{String: "<P>"}}},
	{"html", []*Signature{{String: "<!-->"}}},
	{"xml", []*Signature{{String: "<?XML"}}},
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
	HEX    string
	String string
	b      []byte
}

func (s *Signature) parse() error {
	if s.b != nil {
		return nil
	}
	if s.HEX != "" {
		return s.parseHEX()
	}
	s.b = []byte(s.String)
	return nil
}

func (s *Signature) parseHEX() error {
	bs := strings.Split(s.HEX, " ")
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
	if ext := NODE.Match(b); ext != "" {
		return ext
	}
	return DetectTextExtension(b)
}

func DetectTextExtension(b []byte) string {
	b = bytes.TrimLeft(b, "\t\n\x0c\r ")
	return NODEForText.Match(b)
}

func DetectMIME(b []byte) string {
	ext := DetectExtension(b)
	if ext == "" {
		return ext
	}
	return MIMEMap[ext]
}

func init() {
	NODE = NewNode(false)
	for _, d := range Definitions {
		if err := d.Parse(); err != nil {
			panic(err)
		}
		NODE.Insert(d)
	}
	NODEForText = NewNode(true)
	for _, d := range DefinitionsForText {
		if err := d.Parse(); err != nil {
			panic(err)
		}
		NODEForText.Insert(d)
	}
}
