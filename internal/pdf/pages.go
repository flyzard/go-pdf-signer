package pdf

import "fmt"

// FindPageRef resolves a logical page index (0-based) to the Ref of the
// corresponding /Page leaf in the /Pages tree. index == -1 selects the
// last page.
func (doc *Document) FindPageRef(index int) (Ref, error) {
	pagesRef, ok := doc.Catalog["Pages"].(Ref)
	if !ok {
		return Ref{}, fmt.Errorf("catalog /Pages is not a reference")
	}
	pagesDict, err := doc.ReadDictObject(pagesRef)
	if err != nil {
		return Ref{}, fmt.Errorf("read /Pages: %w", err)
	}
	total, _ := pagesDict.GetInt("Count")
	if total <= 0 {
		return Ref{}, fmt.Errorf("/Pages /Count is zero or missing")
	}

	target := index
	if target < 0 {
		target = total + index
	}
	if target < 0 || target >= total {
		return Ref{}, fmt.Errorf("page index %d out of range [0..%d]", index, total-1)
	}

	ref, err := doc.resolvePageAt(pagesRef, target)
	if err != nil {
		return Ref{}, err
	}
	return ref, nil
}

// resolvePageAt walks the /Pages tree depth-first to locate the page at
// the given 0-based linear position. Handles arbitrarily nested /Pages
// intermediate nodes per ISO 32000-1 §7.7.3.
func (doc *Document) resolvePageAt(nodeRef Ref, linearIndex int) (Ref, error) {
	dict, err := doc.ReadDictObject(nodeRef)
	if err != nil {
		return Ref{}, fmt.Errorf("read page tree node %v: %w", nodeRef, err)
	}
	kids, ok := dict.GetArray("Kids")
	if !ok {
		// Leaf /Page.
		if linearIndex == 0 {
			return nodeRef, nil
		}
		return Ref{}, fmt.Errorf("linearIndex %d overshoots a leaf page", linearIndex)
	}
	remaining := linearIndex
	for _, kid := range kids {
		kidRef, ok := kid.(Ref)
		if !ok {
			return Ref{}, fmt.Errorf("/Kids entry is not a Ref: %T", kid)
		}
		kidDict, err := doc.ReadDictObject(kidRef)
		if err != nil {
			return Ref{}, fmt.Errorf("read kid %v: %w", kidRef, err)
		}
		// Count: for /Pages intermediates it's the subtree size; for /Page
		// leaves no /Count is present, so a single leaf counts as 1.
		count, hasCount := kidDict.GetInt("Count")
		if !hasCount {
			count = 1
		}
		if remaining < count {
			return doc.resolvePageAt(kidRef, remaining)
		}
		remaining -= count
	}
	return Ref{}, fmt.Errorf("linearIndex %d exceeded /Kids traversal", linearIndex)
}

// PageDict returns a shallow copy of the page object's dictionary for
// caller-side mutation. Use Writer.ReplaceObject to emit the updated dict.
func (doc *Document) PageDict(ref Ref) (Dict, error) {
	d, err := doc.ReadDictObject(ref)
	if err != nil {
		return nil, err
	}
	return d.Clone(), nil
}
