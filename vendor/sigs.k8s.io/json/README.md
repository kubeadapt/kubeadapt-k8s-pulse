***REMOVED*** sigs.k8s.io/json

[![Go Reference](https://pkg.go.dev/badge/sigs.k8s.io/json.svg)](https://pkg.go.dev/sigs.k8s.io/json)

***REMOVED******REMOVED*** Introduction

This library is a subproject of [sig-api-machinery](https://github.com/kubernetes/community/tree/master/sig-api-machinery***REMOVED***json).
It provides case-sensitive, integer-preserving JSON unmarshaling functions based on `encoding/json` `Unmarshal()`.

***REMOVED******REMOVED*** Compatibility

The `UnmarshalCaseSensitivePreserveInts()` function behaves like `encoding/json***REMOVED***Unmarshal()` with the following differences:

- JSON object keys are treated case-sensitively.
  Object keys must exactly match json tag names (for tagged struct fields)
  or struct field names (for untagged struct fields).
- JSON integers are unmarshaled into `interface{}` fields as an `int64` instead of a 
  `float64` when possible, falling back to `float64` on any parse or overflow error.
- Syntax errors do not return an `encoding/json` `*SyntaxError` error.
  Instead, they return an error which can be passed to `SyntaxErrorOffset()` to obtain an offset.

***REMOVED******REMOVED*** Additional capabilities

The `UnmarshalStrict()` function decodes identically to `UnmarshalCaseSensitivePreserveInts()`,
and also returns non-fatal strict errors encountered while decoding:

- Duplicate fields encountered
- Unknown fields encountered

***REMOVED******REMOVED******REMOVED*** Community, discussion, contribution, and support

You can reach the maintainers of this project via the 
[sig-api-machinery mailing list / channels](https://github.com/kubernetes/community/tree/master/sig-api-machinery***REMOVED***contact).

***REMOVED******REMOVED******REMOVED*** Code of conduct

Participation in the Kubernetes community is governed by the [Kubernetes Code of Conduct](code-of-conduct.md).

[owners]: https://git.k8s.io/community/contributors/guide/owners.md
[Creative Commons 4.0]: https://git.k8s.io/website/LICENSE
