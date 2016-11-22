package magic

import (
	"fmt"
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
}

// This definition according to http://www.garykessler.net/library/file_sigs.html
var Definitions = []*Definition{
	{"pic", []*Signature{{Bytes: "00"}}}, // mov, pif, sea, ytr
	{"xxx", []*Signature{{Bytes: "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"}}},
	{"pdb", []*Signature{{Offset: 11, Bytes: "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"}}},
	{"rvt", []*Signature{{Bytes: "D0 CF 11 E0 A1 B1 1A E1"}, {Offset: 512, Bytes: "00 00 00 00 00 00 00 00"}}},
	{"jp2", []*Signature{{Bytes: "00 00 00 0C 6A 50 20 20 0D 0A"}}},
	{"3gp", []*Signature{{Bytes: "00 00 00"}, {Offset: 4, Bytes: "66 74 79 70 33 67 70"}}}, // 3gg, 3g2
	{"mp4", []*Signature{{Bytes: "00 00 00 14 66 74 79 70 69 73 6F 6D"}}},
	{"mov", []*Signature{{Bytes: "00 00 00 14 66 74 79 70 71 74 20 20"}}},
	{"mp4", []*Signature{{Bytes: "00 00 00 18 66 74 79 70 33 67 70 35"}}},
	{"m4v", []*Signature{{Bytes: "00 00 00 18 66 74 79 70 6D 70 34 32"}}},
	{"mp4", []*Signature{{Bytes: "00 00 00 1C 66 74 79 70 4D 53 4E 56 01 29 00 46 4D 53 4E 56 6D 70 34 32"}}},
	{"m4a", []*Signature{{Bytes: "00 00 00 20 66 74 79 70 4D 34 41 20"}}},
	{"ico", []*Signature{{Bytes: "00 00 01 00"}}},  // spl
	{"mpeg", []*Signature{{Bytes: "00 00 01 B0"}}}, // mpg
	{"mpeg", []*Signature{{Bytes: "00 00 01 B1"}}}, // mpg
	{"mpeg", []*Signature{{Bytes: "00 00 01 B2"}}}, // mpg
	{"mpeg", []*Signature{{Bytes: "00 00 01 B3"}}}, // mpg
	{"mpeg", []*Signature{{Bytes: "00 00 01 B4"}}}, // mpg
	{"mpeg", []*Signature{{Bytes: "00 00 01 B5"}}}, // mpg
	{"mpeg", []*Signature{{Bytes: "00 00 01 B6"}}}, // mpg
	{"mpeg", []*Signature{{Bytes: "00 00 01 B7"}}}, // mpg
	{"mpeg", []*Signature{{Bytes: "00 00 01 B8"}}}, // mpg
	{"mpeg", []*Signature{{Bytes: "00 00 01 B9"}}}, // mpg
	{"mpeg", []*Signature{{Bytes: "00 00 01 BB"}}}, // mpg
	{"mpeg", []*Signature{{Bytes: "00 00 01 BC"}}}, // mpg
	{"mpeg", []*Signature{{Bytes: "00 00 01 BD"}}}, // mpg
	{"mpeg", []*Signature{{Bytes: "00 00 01 BE"}}}, // mpg
	{"mpeg", []*Signature{{Bytes: "00 00 01 BF"}}}, // mpg
	{"vob", []*Signature{{Bytes: "00 00 01 BA"}}},  // mpg
	{"cur", []*Signature{{Bytes: "00 00 02 00"}}},  // wb2
	{"wk1", []*Signature{{Bytes: "00 00 02 00 06 04 06 00 08 00 00 00 00 00"}}},
	{"wk3", []*Signature{{Bytes: "00 00 1A 00 00 10 04 00 00 00 00 00"}}},
	{"wk4", []*Signature{{Bytes: "00 00 1A 00 02 10 04 00 00 00 00 00"}}}, // wk5
	{"123", []*Signature{{Bytes: "00 00 1A 00 05 10 04"}}},
	{"qxd", []*Signature{{Bytes: "00 00 49 49 58 50 52"}}},
	{"qxd", []*Signature{{Bytes: "00 00 4D 4D 58 50 52"}}},
	{"", []*Signature{{Bytes: "00 00 FE FF"}}},
	{"hlp", []*Signature{{Offset: 6, Bytes: "00 00 FF FF FF FF"}}},
	{"ttf", []*Signature{{Bytes: "00 01 00 00 00"}}},
	{"mny", []*Signature{{Bytes: "00 01 00 00 4D 53 49 53 41 4D 20 44 61 74 61 62 61 73 65"}}},
	{"accdb", []*Signature{{Bytes: "00 01 00 00 53 74 61 6E 64 61 72 64 20 41 43 45 20 44 42"}}},
	{"mdb", []*Signature{{Bytes: "00 01 00 00 53 74 61 6E 64 61 72 64 20 4A 65 74 20 44 42"}}},
	{"img", []*Signature{{Bytes: "00 01 00 08 00 01 00 01 01"}}},
	{"flt", []*Signature{{Bytes: "00 01 01"}}},
	{"aba", []*Signature{{Bytes: "00 01 42 41"}}},
	{"dba", []*Signature{{Bytes: "00 01 42 44"}}},
	{"db", []*Signature{{Bytes: "00 06 15 61 00 00 00 02 00 00 04 D2 00 00 10 00"}}},
	{"", []*Signature{{Bytes: "00 0D BB A0"}}},
	{"fli", []*Signature{{Bytes: "00 11 AF"}}},
	{"", []*Signature{{Bytes: "00 14 00 00 01 02"}, {Offset: 8, Bytes: "03"}}},
	{"snm", []*Signature{{Bytes: "00 1E 84 90 00 00 00 00"}}},
	{"enc", []*Signature{{Bytes: "00 5C 41 B1 FF"}}},
	{"sol", []*Signature{{Bytes: "00 BF"}}},
	{"mdf", []*Signature{{Bytes: "00 FF FF FF FF FF FF FF FF FF FF 00 00 02 00 01"}}},
	{"emf", []*Signature{{Bytes: "01 00 00 00"}}},
	{"pic", []*Signature{{Bytes: "01 00 00 00 01"}}},
	{"wmf", []*Signature{{Bytes: "01 00 09 00 00 03"}}},
	{"fdb", []*Signature{{Bytes: "01 00 39 30"}}}, // gdb
	{"mdf", []*Signature{{Bytes: "01 0F 00 00"}}},
	{"tr1", []*Signature{{Bytes: "01 10"}}},
	{"rgb", []*Signature{{Bytes: "01 DA 01 01 00 03"}}},
	{"drw", []*Signature{{Bytes: "01 FF 02 04 03 02"}}},
	{"dss", []*Signature{{Bytes: "02 64 73 73"}}},
	{"dat", []*Signature{{Bytes: "03"}}}, // db3
	{"qph", []*Signature{{Bytes: "03 00 00 00"}}},
	{"adx", []*Signature{{Bytes: "03 00 00 00 41 50 50 52"}}},
	{"db4", []*Signature{{Bytes: "04"}}},
	{"", []*Signature{{Bytes: "04 00 00 00"}, {Offset: 12, Bytes: "20 03 00 00"}}},
	{"", []*Signature{{Bytes: "05 00 00 00"}, {Offset: 12, Bytes: "20 03 00 00"}}},
	{"drw", []*Signature{{Bytes: "07"}}},
	{"skf", []*Signature{{Bytes: "07 53 4B 46"}}},
	{"dtd", []*Signature{{Bytes: "07 64 74 32 64 64 74 64"}}},
	{"db", []*Signature{{Bytes: "08"}}},
	{"", []*Signature{{Bytes: "08 00 45"}}},
	{"pcx", []*Signature{{Bytes: "0A"}, {Offset: 2, Bytes: "01 01"}}},
	{"wallet", []*Signature{{Bytes: "0A 16 6F 72 67 2E 62 69 74 63 6F 69 6E 2E 70 72"}}},
	{"mp", []*Signature{{Bytes: "0C ED"}}},
	{"doc", []*Signature{{Bytes: "0D 44 4F 43"}}},
	{"nri", []*Signature{{Bytes: "0E 4E 65 72 6F 49 53 4F"}}},
	{"wks", []*Signature{{Bytes: "0E 57 4B 53"}}},
	{"cl5", []*Signature{{Bytes: "10 00 00 00"}}},
	{"ntf", []*Signature{{Bytes: "1A 00 00"}}},
	{"nsf", []*Signature{{Bytes: "1A 00 00 04 00 00"}}},
	{"arc", []*Signature{{Bytes: "1A 02"}}},
	{"arc", []*Signature{{Bytes: "1A 03"}}},
	{"arc", []*Signature{{Bytes: "1A 04"}}},
	{"arc", []*Signature{{Bytes: "1A 08"}}},
	{"arc", []*Signature{{Bytes: "1A 09"}}},
	{"pak", []*Signature{{Bytes: "1A 0B"}}},
	{"eth", []*Signature{{Bytes: "1A 35 01 00"}}},
	{"webm", []*Signature{{Bytes: "1A 45 DF A3"}}},
	{"mkv", []*Signature{{Bytes: "1A 45 DF A3 93 42 82 88 6D 61 74 72 6F 73 6B 61"}}},
	{"jar", []*Signature{{Offset: 14, Bytes: "1A 4A 61 72 1B"}}},
	{"dat", []*Signature{{Bytes: "1A 52 54 53 20 43 4F 4D 50 52 45 53 53 45 44 20 49 4D 41 47 45 20 56 31 2E 30 1A"}}},
	{"ws", []*Signature{{Bytes: "1D 7D"}}},
	{"gz", []*Signature{{Bytes: "1F 8B 08"}}}, // tgz, vlt
	{"tar.z", []*Signature{{Bytes: "1F 9D"}}},
	{"tar.z", []*Signature{{Bytes: "1F A0"}}},
	{"bsb", []*Signature{{Bytes: "21"}}},
	{"ain", []*Signature{{Bytes: "21 12"}}},
	{"lib", []*Signature{{Bytes: "21 3C 61 72 63 68 3E 0A"}}},
	{"ost", []*Signature{{Bytes: "21 42 44 4E"}}}, // pst
	// {"msi", []*Signature{{Bytes: "23 20"}}}, // Too wide hit range (e.g. .py)
	{"vmdk", []*Signature{{Bytes: "23 20 44 69 73 6B 20 44 65 73 63 72 69 70 74 6F"}}},
	{"dsp", []*Signature{{Bytes: "23 20 4D 69 63 72 6F 73 6F 66 74 20 44 65 76 65 6C 6F 70 65 72 20 53 74 75 64 69 6F"}}},
	{"amr", []*Signature{{Bytes: "23 21 41 4D 52"}}},
	{"sil", []*Signature{{Bytes: "23 21 53 49 4C 4B 0A"}}},
	{"hdr", []*Signature{{Bytes: "23 3F 52 41 44 49 41 4E 43 45 0A"}}},
	{"pec", []*Signature{{Bytes: "23 50 45 43 30 30 30 31 4C 41 3A"}}},
	{"pes", []*Signature{{Bytes: "23 50 45 53 30"}}},
	{"sav", []*Signature{{Bytes: "24 46 4C 32 40 28 23 29 20 53 50 53 53 20 44 41 50 53 46 2D 33 20 30"}}},
	{"eps", []*Signature{{Bytes: "25 21 50 53 2D 41 64 6F 62 65 2D 33 2E 30 20 45 50 53 46 2D 33 20 30"}}},
	{"pdf", []*Signature{{Bytes: "25 50 44 46"}}}, // fdf
	{"fbm", []*Signature{{Bytes: "25 62 69 74 6D 61 70"}}},
	{"hqx", []*Signature{{Bytes: "28 54 68 69 73 20 66 69 6C 65 20 6D 75 73 74 20 62 65 20 63 6F 6E 76 65 72 74 65 64 20 77 69 74 68 20 42 69 6E 48 65 78 20"}}},
	{"log", []*Signature{{Bytes: "2A 2A 2A 20 20 49 6E 73 74 61 6C 6C 61 74 69 6F 2A 2A 2A 20 20 49 6E 73 74 61 6C 6C 61 74 69 6F 6E 20 53 74 61 72 74 65 64 20"}}},
	{"lzh", []*Signature{{Offset: 2, Bytes: "2D 6C 68"}}}, // lha
	{"ivr", []*Signature{{Bytes: "2E 52 45 43"}}},
	{"rm", []*Signature{{Bytes: "2E 52 4D 46"}}}, // rmvb
	{"ra", []*Signature{{Bytes: "2E 52 4D 46 00 00 00 12 00"}}},
	{"ra", []*Signature{{Bytes: "2E 72 61 FD 00"}}},
	{"au", []*Signature{{Bytes: "2E 73 6E 64"}}},
	{"msf", []*Signature{{Bytes: "2F 2F 20 3C 21 2D 2D 20 3C 6D 64 62 3A 6D 6F 72 6B 3A 7A"}}},
	{"cat", []*Signature{{Bytes: "30"}}},
	{"evt", []*Signature{{Bytes: "30 00 00 00 4C 66 4C 65"}}},
	{"wma", []*Signature{{Bytes: "30 26 B2 75 8E 66 CF 11 A6 D9 00 AA 00 62 CE 6C"}}},
	{"ntf", []*Signature{{Bytes: "30 31 4F 52 44 4E 41 4E 43 45 20 53 55 52 56 45 59 20 20 20 20 20 20 20"}}},
	{"", []*Signature{{Bytes: "30 37 30 37 30"}}},
	{"wri", []*Signature{{Bytes: "31 BE"}}},
	{"wri", []*Signature{{Bytes: "32 BE"}}},
	{"pcs", []*Signature{{Bytes: "32 03 10 00 00 00 00 00 00 00 80 00 00 00 FF 00"}}},
	{"", []*Signature{{Bytes: "32 03 10 00 00 00 00 00 00 00 80 00 00 00 FF 00"}}},
	{"7z", []*Signature{{Bytes: "37 7A BC AF 27 1C"}}},
	{"", []*Signature{{Bytes: "37 E4 53 96 C9 DB D6 07"}}},
	{"psd", []*Signature{{Bytes: "38 42 50 53"}}},
	{"sle", []*Signature{{Bytes: "3A 56 45 52 53 49 4F 4E"}}},
	{"asx", []*Signature{{Bytes: "3C"}}}, // xdr
	{"dci", []*Signature{{Bytes: "3C 21 64 6F 63 74 79 70"}}},
	{"gpx", []*Signature{{Bytes: "3C 67 70 78 20 76 65 72 73 69 6F 6E 3D 22 31 2E 31"}}},
	{"manifest", []*Signature{{Bytes: "3C 3F 78 6D 6C 20 76 65 72 73 69 6F 6E 3D"}}},
	{"xul", []*Signature{{Bytes: "3C 3F 78 6D 6C 20 76 65 72 73 69 6F 6E 3D 22 31 2E 30 22 3F 3E"}}},
	{"msc", []*Signature{{Bytes: "3C 3F 78 6D 6C 20 76 65 72 73 69 6F 6E 3D 22 31 2E 30 22 3F 3E 0D 0A 3C 4D 4D 43 5F 43 6F 6E 73 6F 6C 65 46 69 6C 65 20 43 6F 6E 73 6F 6C 65 56 65 72 73 69 6F 6E 3D 22"}}},
	{"csd", []*Signature{{Bytes: "3C 43 73 6F 75 6E 64 53 79 6E 74 68 65 73 69 7A"}}},
	{"mif", []*Signature{{Bytes: "3C 4D 61 6B 65 72 46 69 6C 65 20"}}}, // fm
	{"b85", []*Signature{{Bytes: "3C 7E 36 3C 5C 25 5F 30 67 53 71 68 3B"}}},
	{"wb3", []*Signature{{Offset: 24, Bytes: "3E 00 03 00 FE FF 09 00 06"}}},
	{"gid", []*Signature{{Bytes: "3F 5F 03 00"}}}, // gid
	{"enl", []*Signature{{Offset: 32, Bytes: "40 40 40 20 00 00 40 40 40 40"}}},
	{"dwg", []*Signature{{Bytes: "41 43 31 30"}}},
	{"sle", []*Signature{{Bytes: "41 43 76"}}},
	{"", []*Signature{{Bytes: "41 43 53 44"}}},
	{"aes", []*Signature{{Bytes: "41 45 53"}}},
	{"syw", []*Signature{{Bytes: "41 4D 59 4F"}}},
	{"bag", []*Signature{{Bytes: "41 4F 4C 20 46 65 65 64 62 61 67"}}},
	{"idx", []*Signature{{Bytes: "41 4F 4C 44 42"}}}, // aby
	{"ind", []*Signature{{Bytes: "41 4F 4C 49 44 58"}}},
	{"abi", []*Signature{{Bytes: "41 4F 4C 49 4E 44 45 58"}}},
	{"org", []*Signature{{Bytes: "41 4F 4C 56 4D 31 30 30"}}}, // pfc
	{"dat", []*Signature{{Bytes: "41 56 47 36 5F 49 6E 74 65 67 72 69 74 79 5F 44 61 74 61 62 61 73 65"}}},
	{"arc", []*Signature{{Bytes: "41 72 43 01"}}},
	{"", []*Signature{{Bytes: "42 41 41 44"}}},
	{"vcf", []*Signature{{Bytes: "42 45 47 49 4E 3A 56 43 41 52 44 0D 0A"}}},
	{"bli", []*Signature{{Bytes: "42 4C 49 32 32 33"}}}, // rbi
	{"bmp", []*Signature{{Bytes: "42 4D"}}},             // dib
	{"prc", []*Signature{{Bytes: "42 4F 4F 4B 4D 4F 42 49"}}},
	{"bpg", []*Signature{{Bytes: "42 50 47 FB"}}},
	{"bz2", []*Signature{{Bytes: "42 5A 68"}}}, // tar.bz2, tbz2, tb2
	{"apuf", []*Signature{{Bytes: "42 65 67 69 6E 20 50 75 66 66 65 72 20 44 61 74 61 0D 0A"}}},
	{"bli", []*Signature{{Bytes: "42 6C 69 6E 6B 20 62 79 20 44 2E 54 2E 53"}}},
	{"rtd", []*Signature{{Bytes: "43 23 2B 44 A4 43 4D A5 48 64 72"}}},
	{"cbd", []*Signature{{Bytes: "43 42 46 49 4C 45"}}},
	{"iso", []*Signature{{Bytes: "43 44 30 30 31"}}},
	{"cso", []*Signature{{Bytes: "43 49 53 4F"}}},
	{"db", []*Signature{{Bytes: "43 4D 4D 4D 15 00 00 00"}}},
	{"clb", []*Signature{{Bytes: "43 4D 58 31"}}},
	{"clb", []*Signature{{Bytes: "43 4F 4D 2B"}}},
	{"vmdk", []*Signature{{Bytes: "43 4F 57 44"}}},
	{"cpt", []*Signature{{Bytes: "43 50 54 37 46 49 4C 45"}}},
	{"cpt", []*Signature{{Bytes: "43 50 54 46 49 4C 45"}}},
	{"dat", []*Signature{{Bytes: "43 52 45 47"}}},
	{"cru", []*Signature{{Bytes: "43 52 55 53 48 20 76"}}},
	{"swf", []*Signature{{Bytes: "43 57 53"}}},
	{"cin", []*Signature{{Bytes: "43 61 6C 63 75 6C 75 78 20 49 6E 64 6F 6F 72 20"}}},
	{"ctf", []*Signature{{Bytes: "43 61 74 61 6C 6F 67 20 33 2E 30 30 00"}}},
	{"dat", []*Signature{{Bytes: "43 6C 69 65 6E 74 20 55 72 6C 43 61 63 68 65 20 4D 4D 46 20 56 65 72 20"}}},
	{"dax", []*Signature{{Bytes: "44 41 58 00"}}},
	{"db", []*Signature{{Bytes: "44 42 46 48"}}},
	{"dms", []*Signature{{Bytes: "44 4D 53 21"}}},
	{"adf", []*Signature{{Bytes: "44 4F 53"}}},
	{"dst", []*Signature{{Bytes: "44 53 54 62"}}},
	{"dvr", []*Signature{{Bytes: "44 56 44"}}}, // ifo
	{"cdr", []*Signature{{Bytes: "45 4C 49 54 45 20 43 6F 6D 6D 61 6E 64 65 72 20"}}},
	{"vcd", []*Signature{{Bytes: "45 4E 54 52 59 56 43 44 02 00 00 01 02 00 18 58"}}},
	{"dat", []*Signature{{Bytes: "45 52 46 53 53 41 56 45 44 41 54 41 46 49 4C 45"}}},
	{"mdi", []*Signature{{Bytes: "45 50"}}},
	{"e", []*Signature{{Bytes: "45 56 46 09 0D 0A FF 00"}}},
	{"ex", []*Signature{{Bytes: "45 56 46 32 0D 0A 81"}}},
	{"evtx", []*Signature{{Bytes: "45 6C 66 46 69 6C 65 00"}}},
	{"qbb", []*Signature{{Bytes: "45 86 00 00 06 00"}}},
	{"cpe", []*Signature{{Bytes: "46 41 58 43 4F 56 45 52 2D 56 45 52"}}},
	{"fdb", []*Signature{{Bytes: "46 44 42 48 00"}}},
	{"sbv", []*Signature{{Bytes: "46 45 44 46"}}},
	{"", []*Signature{{Bytes: "46 49 4C 45"}}},
	{"flv", []*Signature{{Bytes: "46 4C 56 01"}}},
	{"aiff", []*Signature{{Bytes: "46 4F 52 4D 00"}}}, // dax
	{"swf", []*Signature{{Bytes: "46 57 53"}}},
	{"eml", []*Signature{{Bytes: "46 72 6F 6D 20 20 20"}}},
	{"eml", []*Signature{{Bytes: "46 72 6F 6D 20 3F 3F 3F"}}},
	{"eml", []*Signature{{Bytes: "46 72 6F 6D 3A 20"}}},
	{"ts", []*Signature{{Bytes: "47"}}}, // tsa, tsv
	{"pat", []*Signature{{Bytes: "47 46 31 50 41 54 43 48"}}},
	{"gif", []*Signature{{Bytes: "47 49 46 38 37 61"}}},
	{"gif", []*Signature{{Bytes: "47 49 46 38 39 61"}}},
	{"pat", []*Signature{{Bytes: "47 50 41 54"}}},
	{"gx2", []*Signature{{Bytes: "47 58 32"}}},
	{"g64", []*Signature{{Bytes: "47 65 6E 65 74 65 63 20 4F 6D 6E 69 63 61 73 74"}}},
	{"xpt", []*Signature{{Bytes: "48 45 41 44 45 52 20 52 45 43 4F 52 44 2A 2A 2A"}}},
	{"sh3", []*Signature{{Bytes: "48 48 47 42 31"}}},
	{"tif", []*Signature{{Bytes: "49 20 49"}}}, // tiff
	{"mp3", []*Signature{{Bytes: "49 44 33"}}},
	{"koz", []*Signature{{Bytes: "49 44 33 03 00 00 00"}}},
	{"crw", []*Signature{{Bytes: "49 49 1A 00 00 00 48 45 41 50 43 43 44 52 02 00"}}},
	{"tif", []*Signature{{Bytes: "49 49 2A 00"}}}, // tiff
	{"cr2", []*Signature{{Bytes: "49 49 2A 00 10 00 00 00 43 52"}}},
	{"db", []*Signature{{Bytes: "49 4D 4D 4D 15 00 00 00"}}},
	{"cab", []*Signature{{Bytes: "49 53 63 28"}}},
	{"lit", []*Signature{{Bytes: "49 54 4F 4C 49 54 4C 53"}}},
	{"chi", []*Signature{{Bytes: "49 54 53 46"}}}, // chm
	{"dat", []*Signature{{Bytes: "49 6E 6E 6F 20 53 65 74 75 70 20 55 6E 69 6E 73 74 61 6C 6C 20 4C 6F 67 20 28 62 29"}}},
	{"ipd", []*Signature{{Bytes: "49 6E 74 65 72 40 63 74 69 76 65 20 50 61 67 65"}}},
	{"jar", []*Signature{{Bytes: "4A 41 52 43 53 00"}}},
	{"art", []*Signature{{Bytes: "4A 47 03 0E"}}},
	{"art", []*Signature{{Bytes: "4A 47 04 0E"}}},
	{"vmdk", []*Signature{{Bytes: "4B 44 4D"}}},
	{"vmdk", []*Signature{{Bytes: "4B 44 4D 56"}}},
	{"kgb", []*Signature{{Bytes: "4B 47 42 5F 61 72 63 68 20 2D"}}},
	{"shd", []*Signature{{Bytes: "4B 49 00 00"}}},
	{"", []*Signature{{Bytes: "4B 57 41 4A 88 F0 27 D1"}}},
	{"lnk", []*Signature{{Bytes: "4C 00 00 00 01 14 02 00"}}},
	{"obj", []*Signature{{Bytes: "4C 01"}}},
	{"dst", []*Signature{{Bytes: "4C 41 3A"}}},
	{"gid", []*Signature{{Bytes: "4C 4E 02 00"}}}, // hlp
	{"e", []*Signature{{Bytes: "4C 56 46 09 0D 0A FF 00"}}},
	{"pdb", []*Signature{{Bytes: "4D 2D 57 20 50 6F 63 6B 65 74 20 44 69 63 74 69"}}},
	{"mar", []*Signature{{Bytes: "4D 41 52 31 00"}}},
	{"mar", []*Signature{{Bytes: "4D 41 52 43"}}},
	{"mar", []*Signature{{Bytes: "4D 41 72 30 00"}}},
	{"mte", []*Signature{{Bytes: "4D 43 57 20 54 65 63 68 6E 6F 67 6F 6C 69 65 73"}}},
	{"hdmp", []*Signature{{Bytes: "4D 44 4D 50 93 A7"}}}, // dmp
	{"mls", []*Signature{{Bytes: "4D 49 4C 45 53"}}},
	{"mls", []*Signature{{Bytes: "4D 4C 53 57"}}},
	{"tif", []*Signature{{Bytes: "4D 4D 00 2A"}}}, // tiff
	{"tif", []*Signature{{Bytes: "4D 4D 00 2B"}}}, // tiff
	{"mmf", []*Signature{{Bytes: "4D 4D 4D 44 00 00"}}},
	{"nvram", []*Signature{{Bytes: "4D 52 56 4E"}}},
	{"cab", []*Signature{{Bytes: "4D 53 43 46"}}}, // ppz, snp
	{"tlb", []*Signature{{Bytes: "4D 53 46 54 02 00 01 00"}}},
	{"wim", []*Signature{{Bytes: "4D 53 57 49 4D"}}},
	{"cdr", []*Signature{{Bytes: "4D 53 5F 56 4F 49 43 45"}}}, // dvf, msv
	{"mid", []*Signature{{Bytes: "4D 54 68 64"}}},             // mid, midi, pcs
	{"dsn", []*Signature{{Bytes: "4D 56"}}},
	{"mls", []*Signature{{Bytes: "4D 56 32 31 34"}}},
	{"mls", []*Signature{{Bytes: "4D 56 32 43"}}},
	{"exe", []*Signature{{Bytes: "4D 5A"}}},                   // dll, scr, ocx, cpl, com
	{"api", []*Signature{{Bytes: "4D 5A 90 00 03 00 00 00"}}}, // ax, flt
	{"zap", []*Signature{{Bytes: "4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF"}}},
	{"pdb", []*Signature{{Bytes: "4D 69 63 72 6F 73 6F 66 74 20 43 2F 43 2B 2B 20"}}},
	{"sln", []*Signature{{Bytes: "4D 69 63 72 6F 73 6F 66 74 20 56 69 73 75 61 6C 20 53 74 75 64 69 6F 20 53 6F 6C 75 74 69 6F 6E 20 46 69 6C 65"}}},
	{"wpl", []*Signature{{Offset: 84, Bytes: "4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 4D 65 64 69 61 20 50 6C 61 79 65 72 20 2D 2D 20"}}},
	{"gdb", []*Signature{{Bytes: "4D 73 52 63 66"}}},
	{"dat", []*Signature{{Bytes: "4E 41 56 54 52 41 46 46 49 43"}}},
	{"jnt", []*Signature{{Bytes: "4E 42 2A 00"}}}, // jtp
	{"nsf", []*Signature{{Bytes: "4E 45 53 4D 1A 01"}}},
	{"ntf", []*Signature{{Bytes: "4E 49 54 46 30"}}},
	{"cod", []*Signature{{Bytes: "4E 61 6D 65 3A 20"}}},
	{"attachment", []*Signature{{Bytes: "4F 50 43 4C 44 41 54"}}},
	{"dbf", []*Signature{{Bytes: "4F 50 4C 44 61 74 61 62 61 73 65 46 69 6C 65"}}},
	{"oga", []*Signature{{Bytes: "4F 67 67 53 00 02 00 00 61 73 65 46 69 6C 65"}}}, // ogg, ogv, ogx
	{"dw4", []*Signature{{Bytes: "4F 7B"}}},
	{"idx", []*Signature{{Bytes: "50 00 00 00 20 00 00 00"}}},
	{"pgm", []*Signature{{Bytes: "50 35 0A"}}},
	{"pak", []*Signature{{Bytes: "50 41 43 4B"}}},
	{"dmp", []*Signature{{Bytes: "50 41 47 45 44 55 36 34"}}},
	{"dmp", []*Signature{{Bytes: "50 41 47 45 44 55 4D 50"}}},
	{"pax", []*Signature{{Bytes: "50 41 58"}}},
	{"dat", []*Signature{{Bytes: "50 45 53 54"}}},
	{"pgd", []*Signature{{Bytes: "50 47 50 64 4D 41 49 4E"}}},
	{"img", []*Signature{{Bytes: "50 49 43 54 00 08"}}},
	{"zip", []*Signature{{Bytes: "50 4B 03 04"}}}, // jar, kmz, kwd, odt, odp, ott, sxc, sxd, sxi, sxw, wmz, xpi, xps, xpt
	{"epub", []*Signature{{Bytes: "50 4B 03 04 0A 00 02 00"}}},
	{"jar", []*Signature{{Bytes: "50 4B 03 04 14 00 08 00 08 00"}}},
	{"zip", []*Signature{{Bytes: "50 4B 05 06"}}},
	{"zip", []*Signature{{Bytes: "50 4B 07 08"}}},
	{"zip", []*Signature{{Offset: 30, Bytes: "50 4B 4C 49 54 45"}}},
	{"zip", []*Signature{{Offset: 526, Bytes: "50 4B 53 70 58"}}},
	// {"docx", []*Signature{{Bytes: "50 4B 03 04 0A 00 02 00"}}}, // docx, xlsx, pptx
	{"grp", []*Signature{{Bytes: "50 4D 43 43"}}},
	{"dat", []*Signature{{Bytes: "50 4E 43 49 55 4E 44 4F"}}},
	{"dat", []*Signature{{Bytes: "50 4D 4F 43 43 4D 4F 43"}}},
	{"puf", []*Signature{{Bytes: "50 55 46 58"}}},
	{"qel", []*Signature{{Offset: 92, Bytes: "51 45 4C 20"}}},
	{"img", []*Signature{{Bytes: "51 46 49 FB"}}},
	{"abd", []*Signature{{Bytes: "51 57 20 56 65 72 2E 20"}}}, // qsd
	{"dat", []*Signature{{Bytes: "52 41 5A 41 54 44 42 31"}}},
	{"reg", []*Signature{{Bytes: "52 45 47 45 44 49 54"}}}, // sud
	{"adf", []*Signature{{Bytes: "52 45 56 4E 55 4D 3A 2C"}}},
	{"ani", []*Signature{{Bytes: "52 49 46 46"}}}, // cmx, cdr, dat, ds4, 4xm
	{"avi", []*Signature{{Bytes: "52 49 46 46"}, {Offset: 8, Bytes: "41 56 49 20 4C 49 53 54"}}},
	{"cda", []*Signature{{Bytes: "52 49 46 46"}, {Offset: 8, Bytes: "43 44 44 41 66 6D 74 20"}}},
	{"qcp", []*Signature{{Bytes: "52 49 46 46"}, {Offset: 8, Bytes: "51 4C 43 4D 66 6D 74 20"}}},
	{"rmi", []*Signature{{Bytes: "52 49 46 46"}, {Offset: 8, Bytes: "52 4D 49 44 64 61 74 61"}}},
	{"wav", []*Signature{{Bytes: "52 49 46 46"}, {Offset: 8, Bytes: "57 41 56 45 66 6D 74 20"}}},
	{"cap", []*Signature{{Bytes: "52 54 53 53"}}},
	{"rar", []*Signature{{Bytes: "52 61 72 21 1A 07 00"}}},
	{"rar", []*Signature{{Bytes: "52 61 72 21 1A 07 01 00"}}},
	{"eml", []*Signature{{Bytes: "52 65 74 75 72 6E 2D 50 61 74 68 3A 20"}}},
	{"pf", []*Signature{{Offset: 4, Bytes: "53 43 43 41"}}},
	{"ast", []*Signature{{Bytes: "53 43 48 6C"}}},
	{"img", []*Signature{{Bytes: "53 43 4D 49"}}},
	{"dpx", []*Signature{{Bytes: "53 44 50 58"}}},
	{"shw", []*Signature{{Bytes: "53 48 4F 57"}}},
	{"cpi", []*Signature{{Bytes: "53 49 45 54 52 4F 4E 49 43 53 20 58 52 44 20 53 43 53 20 58 52 44 20 53 43 41 4E"}}},
	{"fits", []*Signature{{Bytes: "53 49 4D 50 4C 45 20 20 3D 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 54"}}},
	{"sit", []*Signature{{Bytes: "53 49 54 21 00"}}},
	{"sdr", []*Signature{{Bytes: "53 4D 41 52 54 44 52 57"}}},
	{"spf", []*Signature{{Bytes: "53 50 46 49 00"}}},
	{"spvchain", []*Signature{{Bytes: "53 50 56 42"}}},
	{"cnv", []*Signature{{Bytes: "53 51 4C 4F 43 4F 4E 56 48 44 00 00 31 2E 30 00"}}},
	{"db", []*Signature{{Bytes: "53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33 00"}}},
	{"", []*Signature{{Bytes: "53 5A 20 88 F0 27 33 D1"}}},
	{"", []*Signature{{Bytes: "53 5A 44 44 88 F0 27 33"}}},
	{"sym", []*Signature{{Bytes: "53 6D 62 6C"}}},
	{"sit", []*Signature{{Bytes: "53 74 75 66 66 49 74 20 28 63 29 31 39 39 37 2D"}}},
	{"cal", []*Signature{{Bytes: "53 75 70 65 72 43 61 6C 63"}}},
	{"thp", []*Signature{{Bytes: "54 48 50 00"}}},
	{"info", []*Signature{{Bytes: "54 68 69 73 20 69 73 20"}}},
	{"uce", []*Signature{{Bytes: "55 43 45 58"}}},
	{"ufa", []*Signature{{Bytes: "55 46 41 C6 D2 C1"}}},
	{"dat", []*Signature{{Bytes: "55 46 4F 4F 72 62 69 74"}}},
	{"pch", []*Signature{{Bytes: "56 43 50 43 48 30"}}},
	{"ctl", []*Signature{{Bytes: "56 45 52 53 49 4F 4E 20"}}},
	{"mif", []*Signature{{Bytes: "56 65 72 73 69 6F 6E 20"}}},
	{"dat", []*Signature{{Bytes: "57 4D 4D 50"}}},
	{"ws2", []*Signature{{Bytes: "57 53 32 30 30 30"}}},
	{"zip", []*Signature{{Offset: 29152, Bytes: "57 69 6E 5A 69 70"}}},
	{"lwp", []*Signature{{Bytes: "57 6F 72 64 50 72 6F"}}},
	{"eml", []*Signature{{Bytes: "58 2D"}}},
	{"cap", []*Signature{{Bytes: "58 43 50 00"}}},
	{"xpt", []*Signature{{Bytes: "58 50 43 4F 4D 0A 54 79 70 65 4C 69 62"}}},
	{"dpx", []*Signature{{Bytes: "58 50 44 53"}}},
	{"bdr", []*Signature{{Bytes: "58 54"}}},
	{"zoo", []*Signature{{Bytes: "5A 4F 4F 20"}}},
	{"swf", []*Signature{{Bytes: "5A 57 53"}}},
	{"ecf", []*Signature{{Bytes: "5B 47 65 6E 65 72 61 6C 5D 0D 0A 44 69 73 70 6C 61 79 20 4E 61 6D 65 3D 3C 44 69 73 70 6C 61 79 4E 61 6D 65"}}},
	{"vcw", []*Signature{{Bytes: "5B 4D 53 56 43"}}},
	{"dun", []*Signature{{Bytes: "5B 50 68 6F 6E 65 5D"}}},
	{"sam", []*Signature{{Bytes: "5B 56 45 52 5D"}}},
	{"sam", []*Signature{{Bytes: "5B 76 65 72 5D"}}},
	{"vmd", []*Signature{{Bytes: "5B 56 4D 44 5D"}}},
	{"cif", []*Signature{{Offset: 2, Bytes: "5B 56 65 72 73 69 6F 6E"}}},
	{"cpx", []*Signature{{Bytes: "5B 57 69 6E 64 6F 77 73 20 4C 61 74 69 6E 20"}}},
	{"cfg", []*Signature{{Bytes: "5B 66 6C 74 73 69 6D 2E 30 5D"}}},
	{"pls", []*Signature{{Bytes: "5B 70 6C 61 79 6C 69 73 74 5D"}}},
	{"hus", []*Signature{{Bytes: "5D FC C8 00"}}},
	{"jar", []*Signature{{Bytes: "5F 27 A8 89"}}},
	{"cas", []*Signature{{Bytes: "5F 43 41 53 45 5F"}}}, // cbk
	{"arj", []*Signature{{Bytes: "60 EA"}}},
	{"", []*Signature{{Bytes: "62 65 67 69 6E"}}},
	{"b64", []*Signature{{Bytes: "62 65 67 69 6E 2D 62 61 73 65 36 34"}}},
	{"plist", []*Signature{{Bytes: "62 70 6C 69 73 74"}}},
	{"caf", []*Signature{{Bytes: "63 61 66 66"}}},
	{"vhd", []*Signature{{Bytes: "63 6F 6E 65 63 74 69 78"}}},
	{"csh", []*Signature{{Bytes: "63 75 73 68 00 00 00 02 00 00 00"}}},
	{"p10", []*Signature{{Bytes: "64 00 00 00"}}},
	{"dex", []*Signature{{Bytes: "64 65 78 0A"}}},
	{"au", []*Signature{{Bytes: "64 6E 73 2E"}}},
	{"dsw", []*Signature{{Bytes: "64 73 77 66 69 6C 65"}}},
	{"shd", []*Signature{{Bytes: "66 49 00 00"}}},
	{"flac", []*Signature{{Bytes: "66 4C 61 43 00 00 00 22"}}},
	{"mp4", []*Signature{{Offset: 4, Bytes: "66 74 79 70 33 67 70 35"}}},
	{"mp4", []*Signature{{Offset: 4, Bytes: "66 74 79 70 4D 53 4E 56"}}},
	{"m4a", []*Signature{{Offset: 4, Bytes: "66 74 79 70 4D 34 41 20"}}},
	{"mp4", []*Signature{{Offset: 4, Bytes: "66 74 79 70 69 73 6F 6D"}}},
	{"m4v", []*Signature{{Offset: 4, Bytes: "66 74 79 70 6D 70 34 32"}}},
	{"mov", []*Signature{{Offset: 4, Bytes: "66 74 79 70 71 74 20 20"}}},
	{"mov", []*Signature{{Offset: 4, Bytes: "6D 6F 6F 76"}}},
	{"shd", []*Signature{{Bytes: "67 49 00 00"}}},
	{"xcf", []*Signature{{Bytes: "67 69 6d 70 20 78 63 66 20"}}},
	{"shd", []*Signature{{Bytes: "68 49 00 00"}}},
	{"dbb", []*Signature{{Bytes: "6C 33 33 6C"}}},
	{"info", []*Signature{{Bytes: "6D 75 6C 74 69 42 69 74"}}},
	{"", []*Signature{{Bytes: "6F 3C"}}},
	{"", []*Signature{{Bytes: "6F 70 64 61 74 61 30 31"}}},
	{"dat", []*Signature{{Bytes: "72 65 67 66"}}},
	{"acd", []*Signature{{Bytes: "72 69 66 66"}}},
	{"ram", []*Signature{{Bytes: "72 74 73 70 3A 2F 2F"}}},
	{"dat", []*Signature{{Bytes: "73 6C 68 21"}}},
	{"dat", []*Signature{{Bytes: "73 6C 68 2E"}}},
	{"pdb", []*Signature{{Bytes: "73 6D 5F"}}},
	{"cal", []*Signature{{Bytes: "73 72 63 64 6F 63 69 64 3A"}}},
	{"prc", []*Signature{{Offset: 60, Bytes: "74 42 4D 50 4B 6E 57 72"}}},
	{"tar", []*Signature{{Offset: 257, Bytes: "75 73 74 61 72"}}},
	{"exr", []*Signature{{Bytes: "76 2F 31 01"}}},
	{"flt", []*Signature{{Bytes: "76 32 30 30 33 2E 31 30 0D 0A 30 0D 0A"}}},
	{"dmg", []*Signature{{Bytes: "78 01 73 0D 62 62 60"}}},
	{"xar", []*Signature{{Bytes: "78 61 72 21"}}},
	{"info", []*Signature{{Bytes: "7A 62 65 78"}}},
	{"lgc", []*Signature{{Bytes: "7B 0D 0A 6F 20"}}}, // lgd
	{"pwi", []*Signature{{Bytes: "7B 5C 70 77 69"}}},
	{"rtf", []*Signature{{Bytes: "7B 5C 72 74 66 31"}}},
	{"csd", []*Signature{{Bytes: "7C 4B C3 74 E1 C8 53 A4 79 B9 01 1D FC 4F DD 13"}}},
	{"psp", []*Signature{{Bytes: "7E 42 4B 00"}}},
	{"img", []*Signature{{Bytes: "7E 74 2C 01 50 70 02 4D 52 01 00 00 00 08 00 00 00 01 00 00 31 00 00 00 31 00 00 00 43 01 FF 00 01 00 08 00 01 00 00 00 7e 74 2c 01"}}},
	{"", []*Signature{{Bytes: "7F 45 4C 46"}}},
	{"obj", []*Signature{{Bytes: "80"}}},
	{"adx", []*Signature{{Bytes: "80 00 00 20 03 12 04"}}},
	{"cin", []*Signature{{Bytes: "80 2A 5F D7"}}},
	{"wab", []*Signature{{Bytes: "81 32 84 C1 85 05 D0 11 B2 90 00 AA 00 3C F6 76"}}},
	{"wpf", []*Signature{{Bytes: "81 CD AB"}}},
	{"", []*Signature{{Bytes: "86 DD 61"}}},
	{"", []*Signature{{Bytes: "86 DD 62"}}},
	{"", []*Signature{{Bytes: "86 DD 63"}}},
	{"", []*Signature{{Bytes: "86 DD 64"}}},
	{"", []*Signature{{Bytes: "86 DD 65"}}},
	{"", []*Signature{{Bytes: "86 DD 66"}}},
	{"", []*Signature{{Bytes: "86 DD 67"}}},
	{"", []*Signature{{Bytes: "86 DD 68"}}},
	{"", []*Signature{{Bytes: "86 DD 69"}}},
	{"", []*Signature{{Bytes: "86 DD 6A"}}},
	{"", []*Signature{{Bytes: "86 DD 6B"}}},
	{"", []*Signature{{Bytes: "86 DD 6C"}}},
	{"", []*Signature{{Bytes: "86 DD 6D"}}},
	{"", []*Signature{{Bytes: "86 DD 6E"}}},
	{"", []*Signature{{Bytes: "86 DD 6F"}}},
	{"", []*Signature{{Bytes: "86 DD 70"}}},
	{"", []*Signature{{Bytes: "86 DD 71"}}},
	{"", []*Signature{{Bytes: "86 DD 72"}}},
	{"", []*Signature{{Bytes: "86 DD 73"}}},
	{"", []*Signature{{Bytes: "86 DD 74"}}},
	{"", []*Signature{{Bytes: "86 DD 75"}}},
	{"", []*Signature{{Bytes: "86 DD 76"}}},
	{"", []*Signature{{Bytes: "86 DD 77"}}},
	{"", []*Signature{{Bytes: "86 DD 78"}}},
	{"", []*Signature{{Bytes: "86 DD 79"}}},
	{"", []*Signature{{Bytes: "86 DD 7A"}}},
	{"png", []*Signature{{Bytes: "89 50 4E 47 0D 0A 1A 0A"}}},
	{"aw", []*Signature{{Bytes: "8A 01 09 00 00 00 E1 08 00 00 99 19"}}},
	{"hap", []*Signature{{Bytes: "91 33 48 46"}}},
	{"skr", []*Signature{{Bytes: "95 00"}}},
	{"skr", []*Signature{{Bytes: "95 01"}}},
	{"jb2", []*Signature{{Bytes: "97 4A 42 32 0D 0A 1A 0A"}}},
	{"gpg", []*Signature{{Bytes: "99"}}},
	{"pkr", []*Signature{{Bytes: "99 01"}}},
	{"wab", []*Signature{{Bytes: "9C CB CB 8D 13 75 D2 11 91 58 00 C0 4F 79 56 A4"}}},
	{"", []*Signature{{Bytes: "A1 B2 C3 D4"}}},
	{"", []*Signature{{Bytes: "A1 B2 CD 34"}}},
	{"dat", []*Signature{{Bytes: "A9 0D 00 00 00 00 00 00"}}},
	{"qdf", []*Signature{{Bytes: "AC 9E BD 8F 00 00"}}},
	{"", []*Signature{{Bytes: "AC ED"}}},
	{"pdb", []*Signature{{Bytes: "AC ED 00 05 73 72 00 12 62 67 62 6C 69 74 7A 2E"}}},
	{"pwl", []*Signature{{Bytes: "B0 4D 46 43"}}},
	{"dcx", []*Signature{{Bytes: "B1 68 DE 3A"}}},
	{"tib", []*Signature{{Bytes: "B4 6E 68 44"}}},
	{"cal", []*Signature{{Bytes: "B5 A2 B0 B3 B3 B0 A5 B5"}}},
	{"wri", []*Signature{{Bytes: "BE 00 00 00 AB 00 00 00 00 00 00 00 00"}}},
	{"dat", []*Signature{{Bytes: "BE BA FE CA 0F 50 61 6C 6D 53 47 20 44 61 74 61"}}},
	{"jar", []*Signature{{Bytes: "CA FE D0 0D"}}},
	{"acs", []*Signature{{Bytes: "C3 AB CD AB"}}},
	{"eps", []*Signature{{Bytes: "C5 D0 D3 C6"}}},
	{"lbk", []*Signature{{Bytes: "C8 00 79 00"}}},
	{"class", []*Signature{{Bytes: "CA FE BA BE"}}},
	{"", []*Signature{{Bytes: "CD 20 AA AA 02 00 00 00"}}},
	{"jceks", []*Signature{{Bytes: "CE CE CE CE"}}},
	{"", []*Signature{{Bytes: "CE FA ED FE"}}},
	{"doc", []*Signature{{Bytes: "CF 11 E0 A1 B1 1A E1 00"}}},
	{"dbx", []*Signature{{Bytes: "CF AD 12 FE"}}},
	{"", []*Signature{{Bytes: "CF FA ED FE"}}},
	{"xls", []*Signature{{Bytes: "D0 CF 11 E0 A1 B1 1A E1"}}}, // ac, adp, apr, db, msc, msi, mtw, opt, rvt, spo, vsd, wps
	{"ppt", []*Signature{{Bytes: "D0 CF 11 E0 A1 B1 1A E1"}, {Offset: 512, Bytes: "00 6E 1E F0"}}},
	{"xls", []*Signature{{Bytes: "D0 CF 11 E0 A1 B1 1A E1"}, {Offset: 512, Bytes: "09 08 10 00 00 06 05 00"}}},
	{"ppt", []*Signature{{Bytes: "D0 CF 11 E0 A1 B1 1A E1"}, {Offset: 512, Bytes: "0F 00 E8 03"}}},
	{"ppt", []*Signature{{Bytes: "D0 CF 11 E0 A1 B1 1A E1"}, {Offset: 512, Bytes: "A0 46 1D F0"}}},
	{"doc", []*Signature{{Bytes: "D0 CF 11 E0 A1 B1 1A E1"}, {Offset: 512, Bytes: "EC A5 C1 00"}}},
	{"ppt", []*Signature{{Bytes: "D0 CF 11 E0 A1 B1 1A E1"}, {Offset: 512, Bytes: "FD FF FF FF"}, {Offset: 518, Bytes: "00 00"}}},
	{"xls", []*Signature{{Bytes: "D0 CF 11 E0 A1 B1 1A E1"}, {Offset: 512, Bytes: "FD FF FF FF"}, {Offset: 517, Bytes: "00"}}},
	{"xls", []*Signature{{Bytes: "D0 CF 11 E0 A1 B1 1A E1"}, {Offset: 512, Bytes: "FD FF FF FF"}, {Offset: 517, Bytes: "02"}}},
	{"xls", []*Signature{{Bytes: "D0 CF 11 E0 A1 B1 1A E1"}, {Offset: 512, Bytes: "FD FF FF FF 20 00 00 00"}}}, // opt
	{"ftr", []*Signature{{Bytes: "D2 0A 00 00"}}},
	{"arl", []*Signature{{Bytes: "D4 2A"}}},
	{"", []*Signature{{Bytes: "D4 C3 B2 A1"}}},
	{"wmf", []*Signature{{Bytes: "D7 CD C6 9A"}}},
	{"doc", []*Signature{{Bytes: "DB A5 2D 00"}}},
	{"cpl", []*Signature{{Bytes: "DC DC"}}},
	{"efx", []*Signature{{Bytes: "DC FE"}}},
	{"info", []*Signature{{Bytes: "E3 10 00 01 00 00 00 00"}}},
	{"pwl", []*Signature{{Bytes: "E3 82 85 96"}}},
	{"one", []*Signature{{Bytes: "E4 52 5C 7B 8C D8 A7 4D AE B1 53 78 D0 29 96 D3"}}},
	{"com", []*Signature{{Bytes: "E8"}}}, // sys
	{"com", []*Signature{{Bytes: "E9"}}}, // sys
	{"com", []*Signature{{Bytes: "EB"}}}, // sys
	{"img", []*Signature{{Bytes: "EB 3C 90 2A"}}},
	{"", []*Signature{{Bytes: "EB 52 90 2D 46 56 45 2D 46 53 2D"}}},
	{"", []*Signature{{Bytes: "EB 58 90 2D 46 56 45 2D 46 53 2D"}}},
	{"rpm", []*Signature{{Bytes: "ED AB EE DB"}}},
	{"", []*Signature{{Bytes: "EF BB BF"}}},
	{"dat", []*Signature{{Bytes: "F9 BE B4 D9"}}},
	{"pub", []*Signature{{Bytes: "D0 CF 11 E0 A1 B1 1A E1"}, {Offset: 512, Bytes: "FD FF FF FF 02"}}},
	{"qbm", []*Signature{{Bytes: "D0 CF 11 E0 A1 B1 1A E1"}, {Offset: 512, Bytes: "FD FF FF FF 04"}}}, // suo
	{"db", []*Signature{{Bytes: "D0 CF 11 E0 A1 B1 1A E1"}, {Offset: 512, Bytes: "FD FF FF FF"}, {Offset: 524, Bytes: "04 00 00 00"}}},
	{"xz", []*Signature{{Bytes: "F9 BE B4 D9"}}},
	{"", []*Signature{{Bytes: "FE ED FA CE"}}},
	{"", []*Signature{{Bytes: "FE ED FA CF"}}},
	{"jks", []*Signature{{Bytes: "FE ED FE ED"}}},
	{"gho", []*Signature{{Bytes: "FE EF"}}}, // ghs
	{"", []*Signature{{Bytes: "FE FF"}}},
	{"sys", []*Signature{{Bytes: "FF"}}},
	{"wks", []*Signature{{Bytes: "FF 00 02 00 04 04 05 54 02 00"}}},
	{"qrp", []*Signature{{Bytes: "FF 0A 00"}}},
	{"cpi", []*Signature{{Bytes: "FF 46 4F 4E 54"}}},
	{"sys", []*Signature{{Bytes: "FF 4B 45 59 42 20 20 20"}}},
	{"wp", []*Signature{{Bytes: "FF 57 50 43"}}},  // wpd, wpg, wpp, wp5, wp6
	{"mp3", []*Signature{{Bytes: "FF 57 50 43"}}}, // mpeg, mpg
	{"jpg", []*Signature{{Bytes: "FF D8 FF"}}},
	{"aac", []*Signature{{Bytes: "FF F1"}}},
	{"aac", []*Signature{{Bytes: "FF F9"}}},
	{"reg", []*Signature{{Bytes: "FF FE"}}},
	{"", []*Signature{{Bytes: "FF FE 00 00"}}},
	{"mof", []*Signature{{Bytes: "FF FE 23 00 6C 00 69 00 6E 00 65 00 20 00 31 00"}}},
	{"sys", []*Signature{{Bytes: "FF FF FF FF"}}},
}

type Definition struct {
	Extension  string
	Signatures []*Signature
}

func (d *Definition) Parse() error {
	for _, s := range d.Signatures {
		if err := s.parse(); err != nil {
			fmt.Println(d.Extension)
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
