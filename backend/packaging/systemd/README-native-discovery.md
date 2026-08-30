# Native discovery privilege profiles

The default `dbpilot-agent.service` runs as the unprivileged `dbpilot` account
with an empty capability bounding, ambient and effective set. Native discovery
always uses the same `dbpilot-agent proc-helper` binary through the fixed
`/run/dbpilot-agent/proc-helper.sock` AF_UNIX protocol. This is one helper per
host, not one helper or plugin per database instance.

On current Linux/systemd, the helper runs as the distinct `dbpilot-proc`
identity with only `CAP_SYS_PTRACE`. `/etc/dbpilot/proc-helper.env` contains a
root-owned finite database process-name allowlist. The helper independently
rejects any PID outside that list before returning bounded facts or socket
inode numbers; the Agent's signed discovery rules apply a second filter.

Stock CentOS 7 uses Linux 3.10 and systemd 219. It has no pidfd API and cannot
grant ambient capabilities to the non-root Agent. On that profile, install and
enable these files together:

- `dbpilot-agent-proc-helper.socket`
- `dbpilot-agent-proc-helper.service`
- `dbpilot-agent.service.d/centos7-proc-helper.conf`
- `/etc/dbpilot/proc-helper.env`, created from `proc-helper.env.example` with the
  package-created `dbpilot` UID and GID

Install `dbpilot-agent-proc-helper.service.d/centos7.conf` on CentOS 7. The
socket-activated helper then runs as root with exactly `CAP_SYS_PTRACE` and
`CAP_DAC_READ_SEARCH`; the main Agent remains capability-free. The fixed
binary protocol accepts only a PID and bounded operation, never paths, file
descriptors, environment reads, shell text or commands. It verifies the exact
Agent UID and GID with `SO_PEERCRED`.

If the selected helper is absent, unhealthy, or rejects the peer, native
discovery reports `permission_denied` / `legacy_proc_helper_unavailable` and
the unrelated Agent telemetry and control services continue running.
