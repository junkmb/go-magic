package magic

import (
	"bytes"
	"errors"
)

var (
	NODE           *Node
	NODEForText    *Node
	ErrNoSignature = errors.New("No signatures in definition")
)

type Node struct {
	Signature       []byte
	Offset          int
	Extension       string
	Children        []*Node
	caseInsensitive bool
}

func NewNode(caseInsensitive bool) *Node {
	return &Node{caseInsensitive: caseInsensitive}
}

func (n *Node) Insert(d *Definition) {
	if len(d.Signatures) == 0 {
		return
	}
	d = copyDefinition(d, n.caseInsensitive)

	for {
		if n.Signature == nil && n.Children == nil {
			n.Signature = d.Signatures[0].b
			n.Offset = d.Signatures[0].Offset
			if len(d.Signatures) > 1 {
				child := &Node{caseInsensitive: n.caseInsensitive}
				n.Children = append(n.Children, child)
				n = child
				d.Signatures = d.Signatures[1:]
				continue
			}
			n.Extension = d.Extension
			return
		}

		i := n.commonLength(d.Signatures[0].b)

		// Split edge
		if i < len(n.Signature) {
			child := &Node{
				Signature:       n.Signature[i:],
				Offset:          n.Offset + i,
				Children:        n.Children,
				Extension:       n.Extension,
				caseInsensitive: n.caseInsensitive,
			}
			n.Signature = n.Signature[:i]
			n.Extension = ""
			n.Children = []*Node{child}
		}

		// Add a child
		if i < len(d.Signatures[0].b) {
			child := n.findChild(d.Signatures[0])
			if child == nil {
				d.Signatures[0].b = d.Signatures[0].b[i:]
				d.Signatures[0].Offset += i
				child = &Node{caseInsensitive: n.caseInsensitive}
				n.Children = append(n.Children, child)
			}
			n = child
		} else if i == len(d.Signatures[0].b) {
			if len(d.Signatures) == 1 {
				n.Extension = d.Extension
				return
			}
			d.Signatures = d.Signatures[1:]
			child := n.findChild(d.Signatures[0])
			if child == nil {
				child = &Node{
					Offset:          d.Signatures[0].Offset,
					caseInsensitive: n.caseInsensitive,
				}
				n.Children = append(n.Children, child)
			}
			n = child
		}
	}
}

func (n *Node) Match(b []byte) string {
	if n.caseInsensitive {
		b = bytes.ToLower(b)
	}
	return n.match(b[n.Offset:])
}

func (n *Node) match(b []byte) (Extension string) {
	if !bytes.HasPrefix(b, n.Signature) {
		return
	}

	for _, child := range n.Children {
		offset := child.Offset - n.Offset
		if len(b) < offset+len(child.Signature) || b[offset] != child.Signature[0] {
			continue
		}
		Extension = child.match(b[offset:])
		if Extension != "" {
			return
		}
	}
	return n.Extension
}

func (n *Node) commonLength(b []byte) (i int) {
	limit := len(n.Signature)
	if x := len(b); x < limit {
		limit = x
	}
	for i < limit && n.Signature[i] == b[i] {
		i++
	}
	return
}

func (n *Node) findChild(s *Signature) *Node {
	for _, child := range n.Children {
		if child.Offset == s.Offset && child.Signature[0] == s.b[0] {
			return child
		}
	}
	return nil
}

func copyDefinition(src *Definition, toLower bool) *Definition {
	return &Definition{
		Extension:  src.Extension,
		Signatures: copySignatures(src.Signatures, toLower),
	}
}

func copySignatures(src []*Signature, toLower bool) (dst []*Signature) {
	dst = make([]*Signature, len(src))
	for i, s := range src {
		dst[i] = &Signature{
			Offset: s.Offset,
			HEX:    s.HEX,
			String: s.String,
			b:      s.b,
		}
		if toLower {
			dst[i].b = bytes.ToLower(dst[i].b)
		}
	}
	return
}
