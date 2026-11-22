// SPDX-License-Identifier: AGPL-3.0-only

// Package sandbox owns everything the host puts around a third-party plugin
// process: the systemd unit template, the per-plugin resource drop-in, the
// privileged install/remove operations, the digest check that runs before a
// plugin starts, and the narrow systemctl client the agent uses
// (docs/adr/0003-plugin-launch-and-transport.md, ARCH review S2).
//
// # What lives here
//
//   - RenderUnit renders qwq-plugin@<id>.service, qwq-plugin@<id>.socket and
//     the resource drop-in for one plugin from a verified manifest. Every value
//     that reaches a unit file is validated first: a newline, a quote, a
//     backslash or a "%" specifier is rejected instead of escaped, because the
//     generated units are never quoted.
//   - InstallUnit/RemoveUnit write and delete those files (0644, root owned,
//     atomic rename) below /etc/systemd/system.
//   - VerifyEntrypoint re-checks the digest of the installed entrypoint with
//     sdk/pkgfile; the unit runs it as ExecStartPre on every start.
//   - WriteCredential writes the per-plugin token 0600 below the persistent
//     /var/lib/qwq-privileged/creds (ADR-0013) and CreatePluginGroup /
//     RemovePluginGroup manage the private group qwq-p-<id>.
//   - Runtime state (/run/qwq/plugin/<id>, /run/qwq/link,
//     /run/qwq/host/<id>) is declared in a per-plugin tmpfiles.d snippet so it
//     survives a reboot: /run is a tmpfs and the socket unit cannot create the
//     directory it listens on.
//   - Systemctl is the interface the supervisor uses. MainPID is never cached
//     here or above: P2-T1 showed that a cached MainPID is wrong the moment an
//     operator restarts a plugin out of band.
//   - HelperClient sends one UnitSpec to the root helper (cmd/qwq-privileged)
//     over /run/qwq/privileged.sock. The controller runs as the unprivileged
//     qwq user and cannot write /etc/systemd/system, so the helper performs
//     the install; the package still never listens on a socket itself.
//
// # What does not live here
//
// The package never starts a listener, never talks to the plugin, and never
// decides whether a plugin may run: polkit (deployments/polkit) lets the agent
// start and stop units, and the agent owns the Host channel and the supervisor.
// Nothing in this package may be reachable from a plugin process.
//
// The root half of installation is a separate program, not a mode of this
// package: cmd/qwq-privileged is socket activated, refuses to run as non-root,
// and validates every path and command against its configured roots (see
// cmd/qwq-privileged/REPORT.md).
//
// # Units
//
// The packaged templates are deployments/systemd/qwq-plugin@.service and
// qwq-plugin@.socket; byte-identical copies are embedded here so the renderer
// and the package cannot drift (a test enforces it). The packaged template is
// not started directly: a plugin's executable path and digest are only known
// after its package is installed, so the privileged helper renders a concrete
// instance unit per plugin. The helper refuses to run as anything but root on
// Linux; see cmd/qwq/privileged.go.
package sandbox
