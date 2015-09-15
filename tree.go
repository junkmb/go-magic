package magic

import (
	"bytes"
	"errors"
)

var (
	NODE           *Node
	ErrNoSignature = errors.New("No signatures in definition")
)

type Node struct {
	Signature []byte
	Offset    int
	Extension string
	Children  []*Node
}

func (n *Node) Insert(d *Definition) {
	d = copyDefinition(d)
	if len(d.Signatures) == 0 {
		return
	}

	for {
		if n.Signature == nil && n.Children == nil {
			n.Signature = d.Signatures[0].b
			n.Offset = d.Signatures[0].Offset
			if len(d.Signatures) > 1 {
				child := &Node{}
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
				Signature: n.Signature[i:],
				Offset:    n.Offset + i,
				Children:  n.Children,
				Extension: n.Extension,
			}
			n.Signature = n.Signature[:i]
			n.Extension = ""
			n.Children = []*Node{child}
		}

		// Add a child
		if i < len(d.Signatures[0].b) {
			child := n.findChildBySignature(d.Signatures[0])
			if child == nil {
				d.Signatures[0].b = d.Signatures[0].b[i:]
				d.Signatures[0].Offset += i
				child = &Node{}
				n.Children = append(n.Children, child)
			}
			n = child
		} else if i == len(d.Signatures[0].b) {
			if len(d.Signatures) == 1 {
				n.Extension = d.Extension
				return
			}
			d.Signatures = d.Signatures[1:]
			child := n.findChildBySignature(d.Signatures[0])
			if child == nil {
				child = &Node{Offset: d.Signatures[0].Offset}
				n.Children = append(n.Children, child)
			}
			n = child
		}
	}
}

func (n *Node) Match(b []byte) string {
	return n.match(b[n.Offset:])
}

func (n *Node) match(b []byte) (Extension string) {
	if !bytes.HasPrefix(b, n.Signature) {
		return
	}

	for _, child := range n.Children {
		offset := child.Offset - n.Offset
		child := n.findChild(b)
		if child == nil {
			return n.Extension
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

func (n *Node) findChild(b []byte) *Node {
	for _, child := range n.Children {
		offset := child.Offset - n.Offset
		if len(b) >= offset+len(child.Signature) && b[offset] == child.Signature[0] {
			return child
		}
	}
	return nil
}

func (n *Node) findChildBySignature(s *Signature) *Node {
	for _, child := range n.Children {
		if child.Offset == s.Offset && child.Signature[0] == s.b[0] {
			return child
		}
	}
	return nil
}

func copyDefinition(src *Definition) *Definition {
	return &Definition{
		Extension:  src.Extension,
		Signatures: copySignatures(src.Signatures),
	}
}

func copySignatures(src []*Signature) (dst []*Signature) {
	dst = make([]*Signature, len(src))
	for i, s := range src {
		dst[i] = &Signature{
			Offset: s.Offset,
			Bytes:  s.Bytes,
			b:      s.b,
		}
	}
	return
}
