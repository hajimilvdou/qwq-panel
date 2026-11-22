// SPDX-License-Identifier: Apache-2.0

// Package sdk is the root of the qwq plugin SDK module.
//
// Everything a plugin needs at compile time lives in this module: generated
// Platform ABI code (gen/), the plugin runtime helpers (pluginsdk/), the
// manifest validator (manifest/) and the Core Intent Model (coreapi/). The
// module is Apache-2.0 and must not import the host module, so plugins can use
// any license (ADR-0005).
package sdk
