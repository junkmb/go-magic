Developping is in progress.

# go-magic
Read magic byte and detect file's extension or mime-type with pure Go

## Example usage
```go
b, err := ioutil.ReadFile("filename")
if err != nil {
	panic(err)
}
ext := magic.DetectExtension(b)
if ext == "zip" {
	ext, err = magic.DetectZipExtension(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		panic(err)
	}
}
fmt.Println(ext)
```
