// SPDX-License-Identifier: AGPL-3.0-only

// Package peercred reads kernel-provided peer credentials from Unix sockets and
// maps a peer PID to a systemd unit through /proc/<pid>/cgroup. It also keeps a
// pidfd (SO_PEERPIDFD, Linux >= 6.5) so PID reuse cannot confuse the caller.
package peercred

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// soPeerPidfd is SO_PEERPIDFD (Linux 6.5). x/sys/unix does not export it at the
// pinned version, so the numeric value is used directly.
const soPeerPidfd = 0x4d

// Cred is a snapshot of SO_PEERCRED plus an optional pidfd.
type Cred struct {
	PID      int32
	UID      uint32
	GID      uint32
	Pidfd    int
	PidfdOK  bool
	PidfdErr string
}

// Close releases the pidfd, if any.
func (c Cred) Close() {
	if c.Pidfd > 0 {
		_ = unix.Close(c.Pidfd)
	}
}

// FromSyscallConn reads SO_PEERCRED and, when the kernel supports it,
// SO_PEERPIDFD from a connected Unix socket.
func FromSyscallConn(sc syscall.Conn) (Cred, error) {
	raw, err := sc.SyscallConn()
	if err != nil {
		return Cred{}, err
	}
	var (
		cred    Cred
		credErr error
	)
	if err := raw.Control(func(fd uintptr) {
		u, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if err != nil {
			credErr = err
			return
		}
		cred.PID, cred.UID, cred.GID = u.Pid, u.Uid, u.Gid
		pidfd, err := getsockoptPeerPidfd(int(fd))
		if err != nil {
			cred.PidfdErr = err.Error()
			return
		}
		cred.Pidfd, cred.PidfdOK = pidfd, true
	}); err != nil {
		return Cred{}, err
	}
	if credErr != nil {
		return Cred{}, credErr
	}
	return cred, nil
}

func getsockoptPeerPidfd(fd int) (int, error) {
	var (
		pidfd int32
		size  = uint32(4)
	)
	_, _, errno := unix.Syscall6(
		unix.SYS_GETSOCKOPT,
		uintptr(fd), uintptr(unix.SOL_SOCKET), uintptr(soPeerPidfd),
		uintptr(unsafe.Pointer(&pidfd)), uintptr(unsafe.Pointer(&size)), 0,
	)
	if errno != 0 {
		return 0, errno
	}
	if pidfd <= 0 {
		return 0, fmt.Errorf("SO_PEERPIDFD returned fd %d", pidfd)
	}
	return int(pidfd), nil
}

// Alive reports whether the peer is still the same process. It uses the pidfd
// when available (no PID reuse window) and falls back to signal 0.
func (c Cred) Alive() error {
	if c.PidfdOK && c.Pidfd > 0 {
		if err := unix.PidfdSendSignal(c.Pidfd, 0, nil, 0); err != nil {
			return fmt.Errorf("pidfd_send_signal: %w", err)
		}
		return nil
	}
	proc, err := os.FindProcess(int(c.PID))
	if err != nil {
		return err
	}
	defer func() { _ = proc.Release() }()
	if err := proc.Signal(syscall.Signal(0)); err != nil {
		return fmt.Errorf("signal 0: %w", err)
	}
	return nil
}

// ProcInfo is the part of a process identity the agent derives from the kernel.
type ProcInfo struct {
	PID       int
	UID       uint32
	Cgroup    string
	Unit      string
	StartTime uint64
}

// ReadProc reads the kernel identity of pid: uid, cgroup, unit and start time.
func ReadProc(pid int) (ProcInfo, error) {
	info := ProcInfo{PID: pid}
	cg, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return info, err
	}
	info.Cgroup = ParseUnifiedCgroup(string(cg))
	info.Unit = UnitFromCgroup(info.Cgroup)
	st, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return info, err
	}
	for _, line := range strings.Split(string(st), "\n") {
		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				uid, err := strconv.ParseUint(fields[1], 10, 32)
				if err == nil {
					info.UID = uint32(uid)
				}
			}
		}
	}
	start, err := StartTime(pid)
	if err != nil {
		return info, err
	}
	info.StartTime = start
	return info, nil
}

// ParseUnifiedCgroup returns the cgroup v2 path from /proc/<pid>/cgroup content.
func ParseUnifiedCgroup(s string) string {
	for _, line := range strings.Split(s, "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) == 3 && parts[0] == "0" && parts[1] == "" {
			return parts[2]
		}
	}
	return ""
}

// UnitFromCgroup returns the unit name that owns a cgroup v2 path.
func UnitFromCgroup(cgroup string) string {
	cgroup = strings.TrimSuffix(strings.TrimSpace(cgroup), "/")
	if cgroup == "" || cgroup == "/" {
		return ""
	}
	idx := strings.LastIndex(cgroup, "/")
	if idx < 0 {
		return cgroup
	}
	return cgroup[idx+1:]
}

// StartTime returns field 22 of /proc/<pid>/stat (clock ticks since boot).
func StartTime(pid int) (uint64, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	s := string(b)
	// comm may contain spaces and parentheses; skip to the last ')'.
	end := strings.LastIndex(s, ")")
	if end < 0 || end+2 >= len(s) {
		return 0, errors.New("malformed /proc stat")
	}
	fields := strings.Fields(s[end+2:])
	// After comm, field 3 is state, so starttime (field 22) is index 19.
	const startTimeIndex = 19
	if len(fields) <= startTimeIndex {
		return 0, errors.New("short /proc stat")
	}
	return strconv.ParseUint(fields[startTimeIndex], 10, 64)
}

// Dialer dials a Unix socket and records the peer credentials of the resulting
// connection. It is compatible with grpc.WithContextDialer.
type Dialer struct {
	path string

	mu   sync.Mutex
	cred Cred
	have bool
}

// NewDialer returns a dialer for the Unix socket at path.
func NewDialer(path string) *Dialer { return &Dialer{path: path} }

// DialContext implements the gRPC context dialer signature.
func (d *Dialer) DialContext(ctx context.Context, _ string) (net.Conn, error) {
	var nd net.Dialer
	conn, err := nd.DialContext(ctx, "unix", d.path)
	if err != nil {
		return nil, err
	}
	sc, ok := conn.(syscall.Conn)
	if !ok {
		_ = conn.Close()
		return nil, errors.New("unix connection is not a syscall.Conn")
	}
	cred, err := FromSyscallConn(sc)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("read peer credentials: %w", err)
	}
	d.mu.Lock()
	d.cred, d.have = cred, true
	d.mu.Unlock()
	return conn, nil
}

// Cred returns the credentials captured by the most recent dial.
func (d *Dialer) Cred() (Cred, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.cred, d.have
}
