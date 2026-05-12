package policy

import "encoding/base64"

// base64StdEnc is a tiny local alias to keep the wire-format constant in one
// place. The phplatform side accepts standard base64 with padding.
func base64StdEnc(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}
