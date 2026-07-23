// Package samlxml provides SAML 2.0 XML structural validators — content-model
// child ordering, ds:Signature placement, ds:KeyName presence, and QName
// namespace resolution — shared across test gates so exactly one implementation
// exists and cannot drift.
//
// It is TEST-SUPPORT ONLY and MUST NOT be imported by production code. It is
// referenced solely from _test.go files and is therefore never linked into the
// binary.
package samlxml

import (
	"fmt"
	"sort"
	"strings"

	"github.com/beevik/etree"
)

// SAML 2.0 namespaces used by the content-model tables and structural checks.
const (
	NSSAML              = "urn:oasis:names:tc:SAML:2.0:assertion"
	NSSAMLP             = "urn:oasis:names:tc:SAML:2.0:protocol"
	NSDS                = "http://www.w3.org/2000/09/xmldsig#"
	NSXMLSchemaInstance = "http://www.w3.org/2001/XMLSchema-instance"
)

// ---------------------------------------------------------------------------
// Content-model tables. Members of an xsd:choice group share a rank and may
// appear in any order among themselves; sequence members have ascending ranks.
// ---------------------------------------------------------------------------

type modelEntry struct {
	ns    string
	local string
	rank  int
}

var assertionModel = []modelEntry{
	{NSSAML, "Issuer", 0},
	{NSDS, "Signature", 1},
	{NSSAML, "Subject", 2},
	{NSSAML, "Conditions", 3},
	{NSSAML, "Advice", 4},
	// xsd:choice of statements — shared rank 5.
	{NSSAML, "Statement", 5},
	{NSSAML, "AuthnStatement", 5},
	{NSSAML, "AuthzDecisionStatement", 5},
	{NSSAML, "AttributeStatement", 5},
}

var responseModel = []modelEntry{
	{NSSAML, "Issuer", 0},
	{NSDS, "Signature", 1},
	{NSSAMLP, "Extensions", 2},
	{NSSAMLP, "Status", 3},
	// xsd:choice — shared rank 4.
	{NSSAML, "Assertion", 4},
	{NSSAML, "EncryptedAssertion", 4},
}

var logoutResponseModel = []modelEntry{
	{NSSAML, "Issuer", 0},
	{NSDS, "Signature", 1},
	{NSSAMLP, "Extensions", 2},
	{NSSAMLP, "Status", 3},
}

func contentModelFor(ns, local string) ([]modelEntry, bool) {
	switch ns + "|" + local {
	case NSSAMLP + "|Response":
		return responseModel, true
	case NSSAMLP + "|LogoutResponse":
		return logoutResponseModel, true
	case NSSAML + "|Assertion":
		return assertionModel, true
	}
	return nil, false
}

func rankOf(model []modelEntry, ns, local string) (int, bool) {
	for _, m := range model {
		if m.ns == ns && m.local == local {
			return m.rank, true
		}
	}
	return 0, false
}

// ---------------------------------------------------------------------------
// Inspection helpers.
// ---------------------------------------------------------------------------

// QName returns an element's prefixed qualified name (space:tag), or the bare
// tag when unprefixed.
func QName(e *etree.Element) string {
	if e.Space != "" {
		return e.Space + ":" + e.Tag
	}
	return e.Tag
}

func observedOrder(e *etree.Element) []string {
	out := make([]string, 0, len(e.ChildElements()))
	for _, c := range e.ChildElements() {
		out = append(out, QName(c))
	}
	return out
}

// DirectChild returns the first direct child element with the given namespace
// URI and local name, or nil.
func DirectChild(e *etree.Element, ns, local string) *etree.Element {
	for _, c := range e.ChildElements() {
		if c.Tag == local && c.NamespaceURI() == ns {
			return c
		}
	}
	return nil
}

// Descend follows a chain of {namespace, local} direct-child steps and returns
// the resolved element, or nil if any step is missing.
func Descend(root *etree.Element, path ...[2]string) *etree.Element {
	cur := root
	for _, step := range path {
		if cur == nil {
			return nil
		}
		cur = DirectChild(cur, step[0], step[1])
	}
	return cur
}

// CollectOrderViolations validates child ordering against the content-model
// tables for every element that has a model, recursing into nested elements.
// Each message includes the observed child order.
func CollectOrderViolations(root *etree.Element) []string {
	var msgs []string
	var walk func(e *etree.Element)
	walk = func(e *etree.Element) {
		if model, ok := contentModelFor(e.NamespaceURI(), e.Tag); ok {
			observed := observedOrder(e)
			lastRank := -1
			for _, c := range e.ChildElements() {
				rank, known := rankOf(model, c.NamespaceURI(), c.Tag)
				if !known {
					msgs = append(msgs, fmt.Sprintf("%s: unexpected child %s (observed order: %v)",
						QName(e), QName(c), observed))
					continue
				}
				if rank < lastRank {
					msgs = append(msgs, fmt.Sprintf("%s: child %s (rank %d) appears after a rank-%d child — sequence violation (observed order: %v)",
						QName(e), QName(c), rank, lastRank, observed))
				}
				if rank > lastRank {
					lastRank = rank
				}
			}
		}
		for _, c := range e.ChildElements() {
			walk(c)
		}
	}
	walk(root)
	return msgs
}

// SignatureImmediatelyAfterIssuer reports whether the root has exactly one direct
// ds:Signature child positioned immediately after Issuer, along with the observed
// child order and the signature count for failure reporting.
func SignatureImmediatelyAfterIssuer(root *etree.Element) (ok bool, observed []string, sigCount int) {
	children := root.ChildElements()
	observed = observedOrder(root)
	issuerIdx := -1
	for i, c := range children {
		if c.Tag == "Issuer" && c.NamespaceURI() == NSSAML {
			issuerIdx = i
			break
		}
	}
	for _, c := range children {
		if c.Tag == "Signature" && c.NamespaceURI() == NSDS {
			sigCount++
		}
	}
	if issuerIdx == -1 || sigCount != 1 || issuerIdx+1 >= len(children) {
		return false, observed, sigCount
	}
	next := children[issuerIdx+1]
	return next.Tag == "Signature" && next.NamespaceURI() == NSDS, observed, sigCount
}

// KeyName returns the ds:KeyName text inside the root's direct ds:Signature
// KeyInfo, whether it exists, and the observed KeyInfo child order.
func KeyName(root *etree.Element) (value string, present bool, keyInfoOrder []string) {
	keyInfo := Descend(root, [2]string{NSDS, "Signature"}, [2]string{NSDS, "KeyInfo"})
	if keyInfo == nil {
		return "", false, nil
	}
	keyInfoOrder = observedOrder(keyInfo)
	kn := DirectChild(keyInfo, NSDS, "KeyName")
	if kn == nil {
		return "", false, keyInfoOrder
	}
	return kn.Text(), true, keyInfoOrder
}

// ---------------------------------------------------------------------------
// Element walker and QName-value namespace resolution.
//
// XML rules: an UNPREFIXED attribute is in no namespace (the default xmlns
// applies to elements, never to attributes). A prefixed name — on an attribute
// or inside a QName-valued attribute — is only meaningful if its prefix resolves
// to an in-scope xmlns binding on the element or an ancestor.
// ---------------------------------------------------------------------------

// WalkElements invokes fn for root and every descendant element, depth-first.
func WalkElements(root *etree.Element, fn func(*etree.Element)) {
	fn(root)
	for _, c := range root.ChildElements() {
		WalkElements(c, fn)
	}
}

// ResolvePrefix resolves an xmlns prefix to its namespace URI using the xmlns
// declarations in scope at el or any ancestor. An empty prefix resolves the
// default namespace declaration.
func ResolvePrefix(el *etree.Element, prefix string) (string, bool) {
	for cur := el; cur != nil; cur = cur.Parent() {
		for _, a := range cur.Attr {
			if prefix == "" {
				if a.Space == "" && a.Key == "xmlns" {
					return a.Value, true
				}
			} else if a.Space == "xmlns" && a.Key == prefix {
				return a.Value, true
			}
		}
	}
	return "", false
}

// InScopePrefixes returns every xmlns binding visible at el (nearest declaration
// wins). The default namespace, if any, is keyed by the empty string.
func InScopePrefixes(el *etree.Element) map[string]string {
	var chain []*etree.Element
	for cur := el; cur != nil; cur = cur.Parent() {
		chain = append(chain, cur)
	}
	bindings := map[string]string{}
	for i := len(chain) - 1; i >= 0; i-- {
		for _, a := range chain[i].Attr {
			switch {
			case a.Space == "xmlns":
				bindings[a.Key] = a.Value
			case a.Space == "" && a.Key == "xmlns":
				bindings[""] = a.Value
			}
		}
	}
	return bindings
}

// SortedPrefixKeys returns the sorted keys of an xmlns-binding map.
func SortedPrefixKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// SplitQName splits a QName value into its prefix and local parts.
func SplitQName(value string) (prefix, local string, hasPrefix bool) {
	if i := strings.IndexByte(value, ':'); i >= 0 {
		return value[:i], value[i+1:], true
	}
	return "", value, false
}
