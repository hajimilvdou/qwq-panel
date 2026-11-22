// SPDX-License-Identifier: AGPL-3.0-only

package doctor

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"strings"
	"testing"
)

type fakeFS map[string]string

func fake(files fakeFS, cmds map[string]string) Env {
	return Env{
		ReadFile: func(p string) ([]byte, error) {
			if s, ok := files[p]; ok {
				return []byte(s), nil
			}
			return nil, fs.ErrNotExist
		},
		Run: func(_ context.Context, name string, args ...string) (string, error) {
			if s, ok := cmds[name]; ok {
				return s, nil
			}
			return "", errors.New("not found")
		},
		Statfs: func(string) (uint64, uint64, error) { return 8 << 30, 24 << 30, nil },
		Stat: func(p string) (os.FileInfo, error) {
			if _, ok := files[p]; ok {
				return nil, nil
			}
			return nil, fs.ErrNotExist
		},
	}
}

func byID(rs []Result) map[string]Result {
	m := map[string]Result{}
	for _, r := range rs {
		m[r.ID] = r
	}
	return m
}

var nsFiles = fakeFS{"/proc/self/ns/mnt": "", "/proc/self/ns/net": "", "/proc/self/ns/pid": "",
	"/proc/self/ns/user": "", "/proc/self/ns/ipc": "", "/proc/self/ns/uts": ""}

func with(base fakeFS, extra fakeFS) fakeFS {
	out := fakeFS{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

// The 1C1G test VPS: Ubuntu 24.04, systemd 255, cgroup v2, KVM, BaoTa + ufw + fail2ban.
func TestTargetHost(t *testing.T) {
	files := with(nsFiles, fakeFS{
		"/etc/os-release":                   "ID=ubuntu\nVERSION_ID=\"24.04\"\nPRETTY_NAME=\"Ubuntu 24.04.3 LTS\"\n",
		"/proc/sys/kernel/osrelease":        "6.8.0-137-generic\n",
		"/sys/fs/cgroup/cgroup.controllers": "cpuset cpu io memory hugetlb pids rdma misc\n",
		"/proc/self/status":                 "Name:\tqwq\nSeccomp:\t0\n",
		"/proc/meminfo":                     "MemTotal:  984064 kB\nMemAvailable: 510000 kB\nSwapTotal: 1048572 kB\n",
		"/www/server/panel":                 "", "/etc/ufw/ufw.conf": "", "/etc/fail2ban/jail.conf": "",
	})
	rs := Run(context.Background(), fake(files, map[string]string{
		"systemctl": "systemd 255 (255.4-1ubuntu8.18)\n+PAM", "systemd-detect-virt": "kvm", "timedatectl": "yes",
	}), Options{DataDir: "/var/lib/qwq"})
	m := byID(rs)
	for _, id := range []string{"os", "kernel", "systemd", "cgroup", "virtualization", "seccomp", "namespaces", "memory", "time", "disk"} {
		if m[id].Status != OK {
			t.Errorf("%s = %+v", id, m[id])
		}
	}
	if m["coexistence"].Status != Info || m["coexistence"].Detail != "found: BaoTa, ufw, fail2ban" {
		t.Errorf("coexistence = %+v", m["coexistence"])
	}
	if Worst(rs) != OK {
		t.Errorf("worst = %s", Worst(rs))
	}
}

// The build host: Ubuntu 20.04, systemd 245, cgroup hybrid.
func TestOldHost(t *testing.T) {
	files := with(nsFiles, fakeFS{
		"/etc/os-release":            "ID=ubuntu\nVERSION_ID=\"20.04\"\nPRETTY_NAME=\"Ubuntu 20.04 LTS\"\n",
		"/proc/sys/kernel/osrelease": "5.4.0-28-generic",
		"/proc/self/status":          "Seccomp:\t0\n",
		"/proc/meminfo":              "MemTotal: 4029440 kB\nMemAvailable: 3400000 kB\nSwapTotal: 2097148 kB\n",
	})
	rs := Run(context.Background(), fake(files, map[string]string{"systemctl": "systemd 245 (245.4)", "systemd-detect-virt": "kvm", "timedatectl": "yes"}), Options{})
	m := byID(rs)
	if m["os"].Status != Warn || m["systemd"].Status != Fail || m["cgroup"].Status != Fail || m["kernel"].Status != Info {
		t.Fatalf("%+v", m)
	}
	if Worst(rs) != Fail {
		t.Fatal("worst should be fail")
	}
}

func TestContainerAndSmallMemory(t *testing.T) {
	files := with(nsFiles, fakeFS{"/proc/meminfo": "MemTotal: 500000 kB\nMemAvailable: 200000 kB\nSwapTotal: 0 kB\n"})
	m := byID(Run(context.Background(), fake(files, map[string]string{"systemd-detect-virt": "openvz"}), Options{}))
	if m["virtualization"].Status != Warn || m["memory"].Status != Warn || m["systemd"].Status != Fail {
		t.Fatalf("%+v", m)
	}
}

// Only Ubuntu 24.04 has been exercised end to end; the other supported
// platforms are accepted but carry a "not verified" note that points at the
// README support table (PRIV-06).
func TestOSVerificationStatus(t *testing.T) {
	for _, c := range []struct {
		release string
		status  Status
		detail  string
	}{
		{"ID=ubuntu\nVERSION_ID=\"24.04\"\nPRETTY_NAME=\"Ubuntu 24.04.3 LTS\"\n", OK, "Ubuntu 24.04.3 LTS"},
		{"ID=ubuntu\nVERSION_ID=\"24.10\"\nPRETTY_NAME=\"Ubuntu 24.10\"\n", OK, "not verified"},
		{"ID=ubuntu\nVERSION_ID=\"22.04\"\nPRETTY_NAME=\"Ubuntu 22.04.5 LTS\"\n", OK, "not verified"},
		{"ID=debian\nVERSION_ID=\"12\"\nPRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\n", OK, "not verified"},
		{"ID=rocky\nVERSION_ID=\"9.4\"\nPRETTY_NAME=\"Rocky Linux 9.4 (Blue Onyx)\"\n", OK, "not verified"},
		{"ID=ubuntu\nVERSION_ID=\"20.04\"\nPRETTY_NAME=\"Ubuntu 20.04 LTS\"\n", Warn, "not a supported distribution"},
	} {
		r := checkOS(fake(fakeFS{"/etc/os-release": c.release}, nil))
		if r.Status != c.status || !strings.Contains(r.Detail, c.detail) {
			t.Errorf("%q = %+v, want %s containing %q", c.release, r, c.status, c.detail)
		}
	}
}

func TestVersionAtLeast(t *testing.T) {
	for _, c := range []struct {
		rel  string
		want bool
	}{{"6.8.0-137-generic", true}, {"6.5.0", true}, {"6.4.16", false}, {"5.15.0", false}, {"7.0", true}, {"bogus", false}} {
		if got := versionAtLeast(c.rel, "6.5"); got != c.want {
			t.Errorf("%s: %v", c.rel, got)
		}
	}
}
