// SPDX-License-Identifier: AGPL-3.0-only

package pluginui

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"net/http"
	"strings"
	"time"
)

//go:embed kit/v1/kit.js kit/v1/kit-base.css
var sharedKitFS embed.FS

// SharedKitPrefix is the read-only host-served URL prefix for the shared
// @qwq/kit v1 ESM bridge and dynamic token base stylesheet. Because it shares
// the panel's origin, sandboxed plugin iframes load it under strict
// `script-src 'self'; style-src 'self'` CSP with zero external dependencies.
const SharedKitPrefix = Prefix + "_kit/v1/"

func serveSharedKit(w http.ResponseWriter, req *http.Request) bool {
	if !strings.HasPrefix(req.URL.Path, SharedKitPrefix) {
		return false
	}
	name := strings.TrimPrefix(req.URL.Path, SharedKitPrefix)
	if name != "kit.js" && name != "kit-base.css" {
		http.NotFound(w, req)
		return true
	}
	data, err := sharedKitFS.ReadFile("kit/v1/" + name)
	if err != nil {
		http.NotFound(w, req)
		return true
	}
	sum := sha256.Sum256(data)
	etag := `"` + hex.EncodeToString(sum[:16]) + `"`

	header := w.Header()
	header.Set("Content-Type", contentType(name))
	header.Set("ETag", etag)
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("Cache-Control", "public, max-age=0, must-revalidate")
	header.Set("Content-Security-Policy", csp(nil))

	http.ServeContent(w, req, name, time.Time{}, bytes.NewReader(data))
	return true
}
