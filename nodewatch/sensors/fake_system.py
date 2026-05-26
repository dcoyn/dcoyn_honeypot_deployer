"""
sensors.fake_system
====================

Per-VM fake "live" system state for the SSH honeypot. Owns a stable
process list (built once, seeded from agent name) and renders snapshots
for `ps`, `top`, `free`, `uptime`, `w`, `df`, `vmstat`, `/proc/meminfo`,
etc.  CPU% and free-memory values drift on every render so two
consecutive `free` calls show different numbers — the box looks live.

The fake universe parameters (org name, ops user, internal IPs) are
pulled from FakeWorld so process command lines and `w` output are
consistent with the rest of the fake filesystem.
"""
from __future__ import annotations

import hashlib
import random
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional

from .fake_world import FakeWorld


# Big-server profile. These get into /proc/cpuinfo, /proc/meminfo,
# lscpu, free, top.
NUM_CPUS    = 32
CPU_MODEL   = "Intel(R) Xeon(R) Platinum 8259CL CPU @ 2.50GHz"
CPU_MHZ     = 2499.998
TOTAL_MEM_KB = 268_435_456   # 256 GiB


@dataclass
class _Proc:
    pid: int
    user: str
    cmd: str
    vsz: int          # virtual size, KB
    rss: int          # resident, KB
    cpu_base: float   # base %CPU — drift is centered around this
    mem_base: float   # base %MEM
    stat: str         # ps stat column (S, Sl, Ss, I<, R, …)
    tty: str = "?"
    start_time: str = "Mar22"  # `ps` start column
    cpu_time: str = "0:00"     # cumulative CPU time
    nice: int = 0
    pr: int = 20


class FakeSystem:
    """Per-VM live-ish system state."""

    NUM_CPUS = NUM_CPUS
    TOTAL_MEM_KB = TOTAL_MEM_KB
    CPU_MODEL = CPU_MODEL

    def __init__(self, world: FakeWorld, hostname: str) -> None:
        self.world = world
        self.hostname = hostname
        self.v = world.values

        # Stable per-VM RNG used for "structural" choices (PIDs, process
        # roster, start times). Run-time drift uses an unseeded RNG so values
        # actually change between calls.
        seed = hashlib.sha256(f"{world.agent_name}|system".encode()).digest()
        self._rng_stable = random.Random(int.from_bytes(seed[:8], "big"))
        self._rng_live = random.Random()

        # Boot time: 30–90 days before THIS process started. Held in the
        # FakeWorld so it persists across sensor restarts (uptime grows
        # naturally between restarts).
        bt_iso = self.v.get("boot_time_iso")
        if bt_iso:
            try:
                self._boot_time = datetime.fromisoformat(bt_iso)
            except Exception:
                self._boot_time = self._fallback_boot_time()
        else:
            self._boot_time = self._fallback_boot_time()

        self._procs: list[_Proc] = self._build_processes()

    def _fallback_boot_time(self) -> datetime:
        days = self._rng_stable.randint(30, 90)
        return datetime.now(timezone.utc) - timedelta(days=days, hours=12,
                                                       minutes=self._rng_stable.randint(0, 59))

    # ------------------------------------------------------------- procs
    def _build_processes(self) -> list[_Proc]:
        r = self._rng_stable
        v = self.v
        org = v.get("org_short", "host")
        int_domain = v.get("int_domain", "internal")

        procs: list[_Proc] = []
        next_pid = [2]

        def pid_seq() -> int:
            p = next_pid[0]
            next_pid[0] += r.randint(1, 3)
            return p

        def pid_jump(min_jump: int = 50) -> int:
            next_pid[0] += r.randint(min_jump, min_jump * 4)
            return pid_seq()

        def cpu_time_str(secs: int) -> str:
            h, m = divmod(secs // 60, 60)
            return f"{h:>3d}:{m:02d}"

        # Random "started ~N days ago" string for the START column
        def start_col() -> str:
            days_ago = r.randint(20, 78)
            d = datetime.now(timezone.utc) - timedelta(days=days_ago)
            return d.strftime("%b%d")

        # --- PID 1: init/systemd ---
        procs.append(_Proc(
            pid=1, user="root", cmd="/sbin/init",
            vsz=168_900, rss=11_420, cpu_base=0.0, mem_base=0.0,
            stat="Ss", start_time=start_col(), cpu_time=cpu_time_str(r.randint(120, 240)),
        ))

        # --- kernel threads ---
        kthread_names = [
            "kthreadd", "rcu_gp", "rcu_par_gp", "slub_flushwq", "netns",
            "mm_percpu_wq", "rcu_preempt", "rcu_sched",
            "migration/0", "migration/1", "migration/2", "migration/3",
            "ksoftirqd/0", "ksoftirqd/1", "ksoftirqd/2", "ksoftirqd/3",
            "cpuhp/0", "cpuhp/1", "cpuhp/2", "cpuhp/3",
            "kdevtmpfs", "inet_frag_wq", "kauditd", "khungtaskd",
            "oom_reaper", "writeback", "kcompactd0", "ksmd", "khugepaged",
            "kintegrityd", "kblockd", "kworker/u4:0-events_unbound",
            "kworker/0:1-events", "kworker/1:0-events", "kworker/2:0-events",
            "kworker/3:0-events", "kworker/0:0H-kblockd",
            "edac-poller", "devfreq_wq", "watchdogd", "kswapd0",
        ]
        for name in kthread_names:
            procs.append(_Proc(
                pid=pid_seq(), user="root", cmd=f"[{name}]",
                vsz=0, rss=0,
                cpu_base=0.0, mem_base=0.0,
                stat=r.choice(["S", "I", "I<", "S<"]),
                start_time=start_col(), cpu_time=cpu_time_str(r.randint(0, 600)),
            ))

        # --- system services ---
        next_pid[0] = max(next_pid[0], 400)
        sys_services = [
            ("systemd-journald",        "root",             70_000,  12_000, "Ss",  0.0, 0.0),
            ("systemd-udevd",           "root",             25_000,   8_000, "Ss",  0.0, 0.0),
            ("/lib/systemd/systemd-resolved", "systemd-resolve", 90_000, 12_000, "Ss", 0.0, 0.0),
            ("/lib/systemd/systemd-networkd", "systemd-network", 90_000, 10_000, "Ss", 0.0, 0.0),
            ("/lib/systemd/systemd-timesyncd", "systemd-timesync", 90_000, 8_000, "Ssl", 0.0, 0.0),
            ("/lib/systemd/systemd-logind", "root",          244_000,   9_000, "Ss",  0.0, 0.0),
            ("dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only",
                                        "messagebus",       12_000,   5_000, "Ss",  0.0, 0.0),
            ("/usr/sbin/rsyslogd -n -iNONE", "syslog",      280_000,  12_000, "Ssl", 0.1, 0.0),
            ("/usr/sbin/cron -f -P",    "root",              8_000,   4_000, "Ss",  0.0, 0.0),
            ("/sbin/agetty -o -p -- \\u --noclear tty1 linux", "root", 6_000, 3_000, "Ss+", 0.0, 0.0),
            ("/usr/sbin/sshd -D",       "root",             16_000,   8_000, "Ss",  0.0, 0.0),
            ("/usr/lib/policykit-1/polkitd --no-debug", "polkitd", 234_000, 16_000, "Ssl", 0.0, 0.0),
            ("/usr/sbin/chronyd -F 1",  "_chrony",          18_000,   4_000, "S",   0.0, 0.0),
            ("/usr/bin/dbus-broker-launch --scope system",
                                        "root",             14_000,   3_500, "Ss",  0.0, 0.0),
        ]
        for cmd, user, vsz, rss, stat, cpu, mem in sys_services:
            procs.append(_Proc(
                pid=pid_jump(50), user=user, cmd=cmd,
                vsz=vsz, rss=rss,
                cpu_base=cpu, mem_base=mem,
                stat=stat, start_time=start_col(),
                cpu_time=cpu_time_str(r.randint(100, 5_000)),
            ))

        # --- postgres family ---
        next_pid[0] = max(next_pid[0], 1200)
        pg_master_pid = pid_seq()
        procs.append(_Proc(
            pid=pg_master_pid, user="postgres",
            cmd="/usr/lib/postgresql/15/bin/postgres -D /var/lib/postgresql/15/main -c config_file=/etc/postgresql/15/main/postgresql.conf",
            vsz=2_415_680, rss=184_320,
            cpu_base=0.4, mem_base=0.07,
            stat="Ss", start_time=start_col(),
            cpu_time=cpu_time_str(r.randint(5_000, 12_000)),
        ))
        for sub in ["checkpointer", "background writer", "walwriter",
                    "autovacuum launcher", "stats collector",
                    "logical replication launcher"]:
            procs.append(_Proc(
                pid=pid_seq(), user="postgres", cmd=f"postgres: {sub}",
                vsz=2_415_680, rss=r.randint(40_000, 200_000),
                cpu_base=r.uniform(0.1, 1.2), mem_base=r.uniform(0.02, 0.08),
                stat="Ss", start_time=start_col(),
                cpu_time=cpu_time_str(r.randint(200, 3_000)),
            ))
        # Idle client backends
        for _ in range(r.randint(8, 14)):
            client_ip = f"10.10.5.{r.randint(40, 70)}"
            procs.append(_Proc(
                pid=pid_seq(), user="postgres",
                cmd=f"postgres: payments payments {client_ip}({r.randint(40_000, 65_000)}) idle",
                vsz=2_415_680, rss=r.randint(80_000, 350_000),
                cpu_base=r.uniform(0.2, 2.4), mem_base=r.uniform(0.03, 0.13),
                stat="Ss", start_time=start_col(),
                cpu_time=cpu_time_str(r.randint(300, 5_000)),
            ))

        # --- redis ---
        next_pid[0] = max(next_pid[0], 4200)
        procs.append(_Proc(
            pid=pid_seq(), user="redis",
            cmd="/usr/bin/redis-server *:6379",
            vsz=567_890, rss=345_678,
            cpu_base=r.uniform(2.0, 4.5), mem_base=r.uniform(0.12, 0.16),
            stat="Ssl", start_time=start_col(),
            cpu_time=cpu_time_str(r.randint(2_000, 6_000)),
        ))

        # --- nginx ---
        next_pid[0] = max(next_pid[0], 3200)
        procs.append(_Proc(
            pid=pid_seq(), user="root",
            cmd="nginx: master process /usr/sbin/nginx -g daemon on; master_process on;",
            vsz=56_000, rss=11_000,
            cpu_base=0.0, mem_base=0.0,
            stat="Ss", start_time=start_col(),
            cpu_time=cpu_time_str(r.randint(20, 100)),
        ))
        for _ in range(self.NUM_CPUS // 2):
            procs.append(_Proc(
                pid=pid_seq(), user="www-data",
                cmd="nginx: worker process",
                vsz=57_000, rss=r.randint(11_000, 18_000),
                cpu_base=r.uniform(0.1, 0.8), mem_base=r.uniform(0.003, 0.007),
                stat="S", start_time=start_col(),
                cpu_time=cpu_time_str(r.randint(300, 1_500)),
            ))

        # --- node app workers ("payments-api") ---
        next_pid[0] = max(next_pid[0], 8400)
        for i in range(8):
            target = r.choice(["index.js", "worker.js", "consumer.js", "scheduler.js"])
            procs.append(_Proc(
                pid=pid_seq(), user="deploy",
                cmd=f"node /opt/app/dist/{target}",
                vsz=3_245_678, rss=r.randint(1_800_000, 2_800_000),
                cpu_base=r.uniform(8.0, 18.0), mem_base=r.uniform(0.7, 1.2),
                stat="Sl", start_time=start_col(),
                cpu_time=cpu_time_str(r.randint(10_000, 24_000)),
            ))

        # --- container runtime / k8s node-like daemons ---
        next_pid[0] = max(next_pid[0], 12000)
        for cmd, user, vsz, rss, cpu, mem, stat in [
            ("/usr/bin/containerd",                            "root", 1_234_567, 234_567, 0.7, 0.09, "Ssl"),
            ("/usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock",
                                                              "root", 1_456_789, 187_654, 0.4, 0.07, "Ssl"),
            ("/usr/local/bin/kubelet --kubeconfig=/etc/kubernetes/kubelet.conf --bootstrap-kubeconfig=/etc/kubernetes/bootstrap-kubelet.conf",
                                                              "root", 1_867_432, 142_876, 1.4, 0.05, "Ssl"),
            ("/usr/local/bin/kube-proxy --config=/var/lib/kube-proxy/config.conf",
                                                              "root",   876_543,  78_654, 0.2, 0.03, "Ssl"),
            ("/usr/local/bin/calico-node -felix",             "root", 1_234_567,  98_765, 0.8, 0.04, "Sl"),
        ]:
            procs.append(_Proc(
                pid=pid_seq(), user=user, cmd=cmd,
                vsz=vsz, rss=rss,
                cpu_base=cpu, mem_base=mem,
                stat=stat, start_time=start_col(),
                cpu_time=cpu_time_str(r.randint(3_000, 12_000)),
            ))

        # --- monitoring agents ---
        next_pid[0] = max(next_pid[0], 16000)
        for cmd, user, vsz, rss, cpu, mem in [
            ("/opt/datadog-agent/bin/agent/agent run", "dd-agent",   456_789, 145_678, 0.7, 0.05),
            ("/opt/datadog-agent/embedded/bin/trace-agent -config /etc/datadog-agent/datadog.yaml",
                                                       "dd-agent",   298_765,  76_543, 0.3, 0.03),
            ("/opt/datadog-agent/embedded/bin/process-agent -config /etc/datadog-agent/datadog.yaml",
                                                       "dd-agent",   312_456,  82_345, 0.4, 0.03),
            ("/usr/sbin/node_exporter --web.listen-address=127.0.0.1:9100",
                                                       "node-exp",   234_567,  23_456, 0.1, 0.009),
            ("/usr/local/bin/fluent-bit -c /etc/fluent-bit/fluent-bit.conf",
                                                       "root",       198_765,  18_432, 0.4, 0.007),
        ]:
            procs.append(_Proc(
                pid=pid_seq(), user=user, cmd=cmd,
                vsz=vsz, rss=rss,
                cpu_base=cpu, mem_base=mem,
                stat="Ssl", start_time=start_col(),
                cpu_time=cpu_time_str(r.randint(1_500, 6_000)),
            ))

        # --- recent / interactive (lower TIME, recent START) ---
        next_pid[0] = max(next_pid[0], 24_000)
        now_str = datetime.now(timezone.utc).strftime("%H:%M")
        procs.append(_Proc(
            pid=pid_seq(), user="deploy",
            cmd=f"sshd: deploy@pts/0",
            vsz=23_456, rss=8_432,
            cpu_base=0.0, mem_base=0.0,
            stat="S", tty="?", start_time=now_str,
            cpu_time="0:00",
        ))
        procs.append(_Proc(
            pid=pid_seq(), user="deploy",
            cmd="-bash",
            vsz=14_567, rss=5_678,
            cpu_base=0.0, mem_base=0.0,
            stat="Ss", tty="pts/0", start_time=now_str,
            cpu_time="0:00",
        ))

        return procs

    # ---------------------------------------------------------- helpers
    def _drift_cpu(self, base: float) -> float:
        """Random walk around base CPU%. Bigger drift for hotter processes."""
        scale = max(0.05, base * 0.25)
        return max(0.0, round(base + self._rng_live.uniform(-scale, scale), 1))

    def _drift_mem(self, base: float) -> float:
        scale = max(0.005, base * 0.05)
        return max(0.0, round(base + self._rng_live.uniform(-scale, scale), 1))

    def _uptime_components(self) -> tuple[int, int, int, int]:
        delta = datetime.now(timezone.utc) - self._boot_time
        days = delta.days
        hours = delta.seconds // 3600
        mins = (delta.seconds % 3600) // 60
        total_seconds = int(delta.total_seconds())
        return days, hours, mins, total_seconds

    def _load_avg(self) -> tuple[float, float, float]:
        # Centered around the sum of process CPU%, normalized by CPU count
        total_cpu = sum(p.cpu_base for p in self._procs)
        base = total_cpu / 100.0 * 1.4  # tuning: ~12-17 for our process set
        l1 = round(base + self._rng_live.uniform(-1.5, 1.5), 2)
        l5 = round(base + self._rng_live.uniform(-1.0, 1.0), 2)
        l15 = round(base + self._rng_live.uniform(-0.7, 0.7), 2)
        return (max(0.0, l1), max(0.0, l5), max(0.0, l15))

    def _mem_snapshot(self) -> dict:
        """Compute a live memory snapshot. Total stays the same; used,
        free, and buff/cache drift."""
        total = self.TOTAL_MEM_KB
        # 62-74% used at any time
        used_pct = self._rng_live.uniform(0.62, 0.74)
        used = int(total * used_pct)
        # 1.5-5 GB really free
        free = self._rng_live.randint(1_500_000, 5_000_000)
        buff_cache = max(0, total - used - free)
        avail = free + buff_cache // 2
        shared = self._rng_live.randint(50_000, 500_000)
        return {
            "total": total, "used": used, "free": free,
            "buff_cache": buff_cache, "available": avail, "shared": shared,
            "swap_total": 0, "swap_used": 0, "swap_free": 0,
        }

    # ---------------------------------------------------------- renderers
    def render_ps_aux(self) -> str:
        lines = ["USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND"]
        for p in self._procs:
            cpu = self._drift_cpu(p.cpu_base)
            mem = self._drift_mem(p.mem_base)
            lines.append(
                f"{p.user:<10s} {p.pid:>5d} {cpu:>4.1f} {mem:>4.1f} "
                f"{p.vsz:>6d} {p.rss:>5d} {p.tty:<8s} {p.stat:<4s} "
                f"{p.start_time:<5s} {p.cpu_time:>6s} {p.cmd}"
            )
        return "\n".join(lines) + "\n"

    def render_ps_ef(self) -> str:
        lines = ["UID          PID    PPID  C STIME TTY          TIME CMD"]
        for p in self._procs:
            ppid = 1 if p.pid > 200 else 0
            lines.append(
                f"{p.user:<10s} {p.pid:>6d} {ppid:>7d} {int(p.cpu_base):>2d} "
                f"{p.start_time:<5s} {p.tty:<10s} {p.cpu_time:>8s} {p.cmd}"
            )
        return "\n".join(lines) + "\n"

    def render_top(self) -> str:
        now = datetime.now(timezone.utc)
        days, hours, mins, _ = self._uptime_components()
        l1, l5, l15 = self._load_avg()
        mem = self._mem_snapshot()

        # Aggregate CPU pct
        total_cpu_pct = sum(self._drift_cpu(p.cpu_base) for p in self._procs)
        us = min(round(total_cpu_pct / self.NUM_CPUS * 0.78, 1), 99.9)
        sy = round(us * 0.25, 1)
        id_ = round(max(0.0, 100.0 - us - sy - 0.3), 1)
        wa = round(self._rng_live.uniform(0.0, 0.4), 1)

        # MiB conversions
        def to_mib(kb): return round(kb / 1024, 1)
        m_total = to_mib(mem["total"])
        m_free  = to_mib(mem["free"])
        m_used  = to_mib(mem["used"])
        m_bc    = to_mib(mem["buff_cache"])
        m_avail = to_mib(mem["available"])

        lines = []
        lines.append(f"top - {now.strftime('%H:%M:%S')} up {days} days, {hours:>2d}:{mins:02d},  "
                     f"3 users,  load average: {l1}, {l5}, {l15}")
        running = sum(1 for p in self._procs if p.stat.startswith("R"))
        sleeping = len(self._procs) - running
        lines.append(f"Tasks: {len(self._procs):>3d} total, {max(running, 2):>3d} running, "
                     f"{sleeping:>3d} sleeping,   0 stopped,   0 zombie")
        lines.append(f"%Cpu(s): {us:>4.1f} us, {sy:>4.1f} sy,  0.0 ni, {id_:>4.1f} id, "
                     f"{wa:>4.1f} wa,  0.0 hi,  0.1 si,  0.0 st")
        lines.append(f"MiB Mem : {m_total:>9.1f} total, {m_free:>9.1f} free, "
                     f"{m_used:>9.1f} used, {m_bc:>9.1f} buff/cache")
        lines.append(f"MiB Swap:       0.0 total,       0.0 free,       0.0 used. {m_avail:>9.1f} avail Mem")
        lines.append("")
        lines.append("    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND")

        # Top 20 by current CPU
        rendered = []
        for p in self._procs:
            rendered.append((self._drift_cpu(p.cpu_base), self._drift_mem(p.mem_base), p))
        rendered.sort(key=lambda x: -x[0])
        for cpu, mem_pct, p in rendered[:20]:
            cmd_short = p.cmd[:40]
            shr = min(p.rss // 4 if p.rss else 0, 99_999)
            lines.append(
                f"{p.pid:>7d} {p.user:<8s} {p.pr:>2d} {p.nice:>3d} "
                f"{p.vsz:>7d} {p.rss:>6d} {shr:>5d} {p.stat[0]} "
                f"{cpu:>5.1f} {mem_pct:>5.1f} {p.cpu_time:>9s}+ {cmd_short}"
            )
        return "\n".join(lines) + "\n"

    def render_free(self, *, human: bool = False, mb: bool = False, gb: bool = False) -> str:
        m = self._mem_snapshot()

        if human:
            def fmt(kb):
                if kb >= 1024**3: return f"{kb / 1024**3:.1f}Ti"
                if kb >= 1024**2: return f"{kb / 1024**2:.1f}Gi"
                if kb >= 1024: return f"{kb / 1024:.0f}Mi"
                return f"{kb}Ki"
        elif mb:
            def fmt(kb): return f"{kb // 1024}"
        elif gb:
            def fmt(kb): return f"{kb // (1024 * 1024)}"
        else:
            def fmt(kb): return f"{kb}"

        return (
            "               total        used        free      shared  buff/cache   available\n"
            f"Mem:      {fmt(m['total']):>11s} {fmt(m['used']):>11s} {fmt(m['free']):>11s} "
            f"{fmt(m['shared']):>11s} {fmt(m['buff_cache']):>11s} {fmt(m['available']):>11s}\n"
            f"Swap:     {fmt(0):>11s} {fmt(0):>11s} {fmt(0):>11s}\n"
        )

    def render_uptime(self) -> str:
        now = datetime.now(timezone.utc)
        days, hours, mins, _ = self._uptime_components()
        l1, l5, l15 = self._load_avg()
        return (f" {now.strftime('%H:%M:%S')} up {days} days, {hours:>2d}:{mins:02d},  "
                f"3 users,  load average: {l1}, {l5}, {l15}\n")

    def render_w(self) -> str:
        now = datetime.now(timezone.utc)
        days, hours, mins, _ = self._uptime_components()
        l1, l5, l15 = self._load_avg()
        head = (f" {now.strftime('%H:%M:%S')} up {days} days, {hours:>2d}:{mins:02d},  "
                f"3 users,  load average: {l1}, {l5}, {l15}\n")
        # Three sessions: a deploy + ops + the attacker's own pts/0
        t_deploy = (now - timedelta(hours=3, minutes=14)).strftime("%H:%M")
        t_ops    = (now - timedelta(hours=1, minutes=42)).strftime("%H:%M")
        t_me     = now.strftime("%H:%M")
        ops_first = self.v.get("ops_first", "ops").lower()
        return head + (
            "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n"
            f"deploy   pts/0    10.10.5.42       {t_deploy}    1:24m  0.05s  0.05s -bash\n"
            f"ops      pts/1    10.10.5.43       {t_ops}   30:42   0.02s  0.02s tail -F /var/log/nginx/api.error.log\n"
            f"{ops_first:<8s} pts/2    10.10.5.44       {t_me}     0.00s  0.08s  0.06s w\n"
        )

    def render_df(self, *, human: bool = False) -> str:
        mounts = [
            ("/dev/nvme0n1p2",    200_000_000, 0.34, "/"),
            ("tmpfs",            134_217_728, 0.00, "/dev/shm"),
            ("tmpfs",             27_307_356, 0.01, "/run"),
            ("/dev/nvme0n1p1",       524_288, 0.18, "/boot/efi"),
            ("/dev/nvme1n1",   2_097_152_000, 0.67, "/var/lib/docker"),
            ("/dev/nvme2n1",   4_194_304_000, 0.42, "/var/lib/postgresql"),
            ("/dev/sdb1",      8_388_608_000, 0.89, "/var/backups"),
            ("/dev/sdc1",     16_777_216_000, 0.71, "/data"),
            ("efivarfs",                 256, 0.50, "/sys/firmware/efi/efivars"),
        ]
        if human:
            def fmt(kb):
                if kb >= 1024**3: return f"{kb / 1024**3:.1f}T"
                if kb >= 1024**2: return f"{kb / 1024**2:.0f}G"
                if kb >= 1024: return f"{kb / 1024:.0f}M"
                return f"{kb}K"
            lines = ["Filesystem        Size  Used Avail Use% Mounted on"]
        else:
            def fmt(kb): return str(kb)
            lines = ["Filesystem        1K-blocks       Used  Available Use% Mounted on"]
        for dev, total, pct, mp in mounts:
            used  = int(total * pct)
            avail = total - used
            lines.append(
                f"{dev:<16s} {fmt(total):>10s} {fmt(used):>10s} {fmt(avail):>10s} "
                f"{int(pct*100):>3d}% {mp}"
            )
        return "\n".join(lines) + "\n"

    def render_vmstat(self) -> str:
        m = self._mem_snapshot()
        us = self._rng_live.randint(10, 22)
        sy = self._rng_live.randint(2, 6)
        return (
            "procs -----------memory---------- ---swap-- -----io---- -system-- ------cpu-----\n"
            " r  b   swpd     free    buff    cache   si   so    bi    bo   in   cs us sy id wa st\n"
            f" 1  0      0 {m['free']:>8d} {self._rng_live.randint(200_000, 800_000):>7d} "
            f"{m['buff_cache']:>8d}    0    0    {self._rng_live.randint(8, 64):>2d}   "
            f"{self._rng_live.randint(120, 220):>3d}  {self._rng_live.randint(700, 1400):>4d} "
            f"{self._rng_live.randint(1300, 1800):>4d} {us:>2d}  {sy:>2d} {100-us-sy:>2d}  0  0\n"
        )

    def render_mpstat(self) -> str:
        now = datetime.now(timezone.utc).strftime("%H:%M:%S")
        us = round(self._rng_live.uniform(15.0, 25.0), 2)
        sy = round(us * 0.25, 2)
        id_ = round(100.0 - us - sy - 0.3, 2)
        return (
            "Linux 5.15.0-91-generic (" + self.hostname + ") \t"
            + datetime.now(timezone.utc).strftime("%m/%d/%Y") + " \t_x86_64_\t"
            + f"({self.NUM_CPUS} CPU)\n\n"
            f"{now}     CPU    %usr   %nice    %sys %iowait    %irq   %soft  %steal  %guest  %gnice   %idle\n"
            f"{now}     all   {us:>5.2f}    0.00   {sy:>5.2f}    0.30    0.00    0.10    0.00    0.00    0.00   {id_:>5.2f}\n"
        )

    def render_nproc(self) -> str:
        return f"{self.NUM_CPUS}\n"

    def render_lscpu(self) -> str:
        return (
            "Architecture:                    x86_64\n"
            "CPU op-mode(s):                  32-bit, 64-bit\n"
            "Byte Order:                      Little Endian\n"
            "Address sizes:                   46 bits physical, 48 bits virtual\n"
            f"CPU(s):                          {self.NUM_CPUS}\n"
            f"On-line CPU(s) list:             0-{self.NUM_CPUS - 1}\n"
            "Thread(s) per core:              2\n"
            "Core(s) per socket:              16\n"
            "Socket(s):                       1\n"
            "NUMA node(s):                    2\n"
            "Vendor ID:                       GenuineIntel\n"
            "CPU family:                      6\n"
            "Model:                           85\n"
            f"Model name:                      {self.CPU_MODEL}\n"
            "Stepping:                        7\n"
            f"CPU MHz:                         {CPU_MHZ}\n"
            "BogoMIPS:                        4999.99\n"
            "Hypervisor vendor:               KVM\n"
            "Virtualization type:             full\n"
            "L1d cache:                       512 KiB\n"
            "L1i cache:                       512 KiB\n"
            "L2 cache:                        16 MiB\n"
            "L3 cache:                        35.8 MiB\n"
            "NUMA node0 CPU(s):               0-15\n"
            "NUMA node1 CPU(s):               16-31\n"
        )

    # --- /proc/* renderers (dynamic) ---
    def render_proc_meminfo(self) -> str:
        m = self._mem_snapshot()
        return (
            f"MemTotal:       {m['total']:>10d} kB\n"
            f"MemFree:        {m['free']:>10d} kB\n"
            f"MemAvailable:   {m['available']:>10d} kB\n"
            f"Buffers:        {self._rng_live.randint(200_000, 800_000):>10d} kB\n"
            f"Cached:         {m['buff_cache']:>10d} kB\n"
            f"SwapCached:              0 kB\n"
            f"Active:         {int(m['used'] * 0.6):>10d} kB\n"
            f"Inactive:       {int(m['used'] * 0.4):>10d} kB\n"
            f"SwapTotal:               0 kB\n"
            f"SwapFree:                0 kB\n"
            f"Dirty:          {self._rng_live.randint(100, 4000):>10d} kB\n"
            f"Writeback:               0 kB\n"
            f"AnonPages:      {int(m['used'] * 0.55):>10d} kB\n"
            f"Mapped:         {self._rng_live.randint(800_000, 1_400_000):>10d} kB\n"
            f"Shmem:          {m['shared']:>10d} kB\n"
            f"Slab:           {self._rng_live.randint(800_000, 1_600_000):>10d} kB\n"
            f"PageTables:     {self._rng_live.randint(20_000, 80_000):>10d} kB\n"
            f"CommitLimit:    {m['total'] // 2:>10d} kB\n"
            f"Committed_AS:   {int(m['used'] * 1.3):>10d} kB\n"
            f"HugePages_Total:         0\n"
            f"HugePages_Free:          0\n"
            f"Hugepagesize:         2048 kB\n"
        )

    def render_proc_loadavg(self) -> str:
        l1, l5, l15 = self._load_avg()
        running = self._rng_live.randint(2, 6)
        return f"{l1} {l5} {l15} {running}/{len(self._procs)} {max(p.pid for p in self._procs) + 1}\n"

    def render_proc_uptime(self) -> str:
        _, _, _, total_secs = self._uptime_components()
        # idle is roughly NUM_CPUS * uptime * (1 - load_avg/NUM_CPUS)
        load = sum(self._load_avg()) / 3.0
        idle = int(self.NUM_CPUS * total_secs * (1 - min(load / self.NUM_CPUS, 0.95)))
        return f"{total_secs}.{self._rng_live.randint(0, 99):02d} {idle}.{self._rng_live.randint(0, 99):02d}\n"

    def render_proc_cpuinfo(self) -> str:
        blocks = []
        for cpu_id in range(self.NUM_CPUS):
            blocks.append(
                f"processor\t: {cpu_id}\n"
                f"vendor_id\t: GenuineIntel\n"
                f"cpu family\t: 6\n"
                f"model\t\t: 85\n"
                f"model name\t: {self.CPU_MODEL}\n"
                f"stepping\t: 7\n"
                f"microcode\t: 0x500320a\n"
                f"cpu MHz\t\t: {CPU_MHZ}\n"
                f"cache size\t: 36608 KB\n"
                f"physical id\t: {cpu_id // 16}\n"
                f"siblings\t: 16\n"
                f"core id\t\t: {cpu_id % 16}\n"
                f"cpu cores\t: 16\n"
                f"apicid\t\t: {cpu_id}\n"
                f"initial apicid\t: {cpu_id}\n"
                f"fpu\t\t: yes\n"
                f"fpu_exception\t: yes\n"
                f"cpuid level\t: 22\n"
                f"wp\t\t: yes\n"
                f"flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ss ht syscall nx pdpe1gb rdtscp lm constant_tsc rep_good nopl xtopology nonstop_tsc cpuid aperfmperf tsc_known_freq pni pclmulqdq monitor ssse3 cx16 pcid sse4_1 sse4_2 x2apic movbe popcnt tsc_deadline_timer aes xsave avx f16c rdrand hypervisor lahf_lm abm 3dnowprefetch invpcid_single ssbd ibrs ibpb stibp ibrs_enhanced fsgsbase tsc_adjust bmi1 hle avx2 smep bmi2 erms invpcid rtm avx512f avx512dq rdseed adx smap clflushopt clwb avx512cd avx512bw avx512vl xsaveopt xsavec xgetbv1 xsaves arat pku ospke avx512_vnni md_clear arch_capabilities\n"
                f"bugs\t\t: spectre_v1 spectre_v2 spec_store_bypass mds swapgs taa\n"
                f"bogomips\t: 4999.99\n"
                f"clflush size\t: 64\n"
                f"cache_alignment\t: 64\n"
                f"address sizes\t: 46 bits physical, 48 bits virtual\n"
                f"power management:\n"
            )
        return "\n".join(blocks) + "\n"


# ----- module-level helpers -----
_DYNAMIC_PROC_PATHS = {
    "/proc/meminfo":  "render_proc_meminfo",
    "/proc/loadavg":  "render_proc_loadavg",
    "/proc/uptime":   "render_proc_uptime",
    "/proc/cpuinfo":  "render_proc_cpuinfo",
}


def render_proc_path(system: FakeSystem, path: str) -> Optional[bytes]:
    """If `path` is a known dynamic /proc entry, return its rendered bytes.
    Otherwise None — caller falls back to the static FakeFS content."""
    method = _DYNAMIC_PROC_PATHS.get(path)
    if method is None:
        return None
    return getattr(system, method)().encode("utf-8")
