package magic

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNode(t *testing.T) {
	n := &Node{}

	// Test inserting
	d := &Definition{
		Extension: "ext1",
		Signatures: []*Signature{
			&Signature{Offset: 0, b: []byte("prefix1")},
		},
	}
	n.Insert(d)
	expect := &Node{
		Signature: []byte("prefix1"),
		Extension: "ext1",
	}
	assert.Equal(t, expect, n)

	d = &Definition{
		Extension: "ext2",
		Signatures: []*Signature{
			&Signature{Offset: 0, b: []byte("prefix1")},
			&Signature{Offset: 10, b: []byte("prefix2")},
		},
	}
	n.Insert(d)
	child := &Node{
		Signature: []byte("prefix2"),
		Offset:    10,
		Extension: "ext2",
	}
	expect.Children = []*Node{child}
	assert.Equal(t, expect, n)

	d = &Definition{
		Extension: "ext3",
		Signatures: []*Signature{
			&Signature{Offset: 0, b: []byte("prefix1")},
			&Signature{Offset: 10, b: []byte("prefix3")},
		},
	}
	n.Insert(d)
	child2 := &Node{
		Signature: []byte("2"),
		Offset:    16,
		Extension: "ext2",
	}
	child3 := &Node{
		Signature: []byte("3"),
		Offset:    16,
		Extension: "ext3",
	}
	child1 := &Node{
		Signature: []byte("prefix"),
		Offset:    10,
		Extension: "",
		Children:  []*Node{child2, child3},
	}
	expect = &Node{
		Signature: []byte("prefix1"),
		Extension: "ext1",
		Children:  []*Node{child1},
	}
	assert.Equal(t, expect, n)

	d = &Definition{
		Extension: "ext0",
		Signatures: []*Signature{
			&Signature{Offset: 0, b: []byte("pref")},
		},
	}
	n.Insert(d)
	child2 = &Node{
		Signature: []byte("2"),
		Offset:    16,
		Extension: "ext2",
	}
	child3 = &Node{
		Signature: []byte("3"),
		Offset:    16,
		Extension: "ext3",
	}
	child1 = &Node{
		Signature: []byte("prefix"),
		Offset:    10,
		Extension: "",
		Children:  []*Node{child2, child3},
	}
	child0 := &Node{
		Signature: []byte("ix1"),
		Offset:    4,
		Extension: "ext1",
		Children:  []*Node{child1},
	}
	expect = &Node{
		Signature: []byte("pref"),
		Extension: "ext0",
		Children:  []*Node{child0},
	}
	assert.Equal(t, expect, n)

	d = &Definition{
		Extension: "ext10",
		Signatures: []*Signature{
			&Signature{Offset: 0, b: []byte("orefix1")},
		},
	}
	n.Insert(d)
	child2 = &Node{
		Signature: []byte("2"),
		Offset:    16,
		Extension: "ext2",
	}
	child3 = &Node{
		Signature: []byte("3"),
		Offset:    16,
		Extension: "ext3",
	}
	child1 = &Node{
		Signature: []byte("prefix"),
		Offset:    10,
		Extension: "",
		Children:  []*Node{child2, child3},
	}
	child0 = &Node{
		Signature: []byte("ix1"),
		Offset:    4,
		Extension: "ext1",
		Children:  []*Node{child1},
	}
	child = &Node{
		Signature: []byte("pref"),
		Extension: "ext0",
		Children:  []*Node{child0},
	}
	brother := &Node{
		Signature: []byte("orefix1"),
		Extension: "ext10",
	}
	expect = &Node{
		Signature: []byte{},
		Children:  []*Node{child, brother},
	}
	assert.Equal(t, expect, n)

	d = &Definition{
		Extension: "ext20",
		Signatures: []*Signature{
			&Signature{Offset: 5, b: []byte("prefix20")},
		},
	}
	n.Insert(d)
	child2 = &Node{
		Signature: []byte("2"),
		Offset:    16,
		Extension: "ext2",
	}
	child3 = &Node{
		Signature: []byte("3"),
		Offset:    16,
		Extension: "ext3",
	}
	child1 = &Node{
		Signature: []byte("prefix"),
		Offset:    10,
		Extension: "",
		Children:  []*Node{child2, child3},
	}
	child0 = &Node{
		Signature: []byte("ix1"),
		Offset:    4,
		Extension: "ext1",
		Children:  []*Node{child1},
	}
	child = &Node{
		Signature: []byte("pref"),
		Extension: "ext0",
		Children:  []*Node{child0},
	}
	brother = &Node{
		Signature: []byte("orefix1"),
		Extension: "ext10",
	}
	brother2 := &Node{
		Signature: []byte("prefix20"),
		Offset:    5,
		Extension: "ext20",
	}
	expect = &Node{
		Signature: []byte{},
		Children:  []*Node{child, brother, brother2},
	}
	assert.Equal(t, expect, n)

	// Test matching
	data := []byte("prefix1")
	assert.Equal(t, "ext1", n.Match(data))

	data = []byte("prefix1foo")
	assert.Equal(t, "ext1", n.Match(data))

	data = []byte("prefix1789prefix2")
	assert.Equal(t, "ext2", n.Match(data))

	data = []byte("prefix1789prefix3")
	assert.Equal(t, "ext3", n.Match(data))

	data = []byte("prefix3")
	assert.Equal(t, "ext0", n.Match(data))

	data = []byte("orefix1")
	assert.Equal(t, "ext10", n.Match(data))

	data = []byte("foobaprefix20")
	assert.Equal(t, "ext20", n.Match(data))

	data = []byte("foobaa")
	assert.Equal(t, "", n.Match(data))
}
