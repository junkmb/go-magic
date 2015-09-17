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
  ext = magic.DetectZipExtension(bytes.NewReader(b), int64(len(b)))
}
fmt.Println(ext)
```
