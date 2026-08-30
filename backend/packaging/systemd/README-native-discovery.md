# Native discovery privilege profiles

The default `dbpilot-agent.service` runs as the unprivileged `dbpilot` account.
It receives only `CAP_SYS_PTRACE`; this permits trusted `/proc/<pid>/exe` reads
and the bounded pidfd socket inspection used on current Linux kernels.

Stock CentOS 7 uses Linux 3.10 and systemd 219. It has no pidfd API and cannot
grant ambient capabilities to the non-root Agent. On that profile, install and
enable these files together:

- `dbpilot-agent-proc-helper.socket`
- `dbpilot-agent-proc-helper.service`
- `dbpilot-agent.service.d/centos7-proc-helper.conf`
- `/etc/dbpilot/proc-helper.env`, created from `proc-helper.env.example` with the
  package-created `dbpilot` UID and GID

Also set `legacy_proc_helper: true` in the Agent configuration. The Agent then
uses a fixed `0600` AF_UNIX socket and holds no discovery capability itself.
The socket-activated helper runs as root with exactly `CAP_SYS_PTRACE` and
`CAP_DAC_READ_SEARCH`. Its fixed binary protocol accepts only a PID and a
bounded operation; it cannot receive paths, environment reads, shell text or
commands. It verifies the caller UID and GID with `SO_PEERCRED`.

If the selected helper is absent, unhealthy, or rejects the peer, native
discovery reports `permission_denied` / `legacy_proc_helper_unavailable` and
the unrelated Agent telemetry and control services continue running.
