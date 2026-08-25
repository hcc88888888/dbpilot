# DBPilot Agent telemetry foundation

`dbpilot-agent` is a single embedded telemetry process for Linux. It does not
install, start, expose, or depend on Vector or a standalone OpenTelemetry
Collector process.

## Supported platforms and installation

Release builds support CentOS 7+ and Kylin V10+ on amd64. Kylin V10+ arm64 is
also supported for the Agent. Install the matching binary at
`/usr/local/bin/dbpilot-agent`, install
`packaging/systemd/dbpilot-agent.service`, copy the example configuration to
`/etc/dbpilot/agent.yaml`, and create a non-login `dbpilot` user.

The service writes only to `/var/lib/dbpilot-agent`. Make that directory and
the configuration/TLS directories owned by `dbpilot:dbpilot`; use mode 0700
for the data directory and 0600 for private keys and configuration. Do not run
the service as root. For journald collection, grant read access through the
host's `systemd-journal` group or an equivalent ACL before starting the unit.

```sh
systemctl daemon-reload
systemctl enable --now dbpilot-agent
systemctl status dbpilot-agent
```

## Bootstrap configuration and trust

The required bootstrap fields are Agent ID, DBPilot server address, CA,
certificate, private-key, policy-public-key, data directory, and allowed log
roots. All secret and data paths must be absolute. The Agent rejects a missing
TLS file, relative path, a world-writable Linux data directory, and an empty
allowed-root list when file collection is enabled.

The bootstrap file is not a policy surface. DBPilot supplies signed, versioned
policy envelopes; the Agent verifies them before activation and only accepts
the closed source kinds `FILE_LOG`, `JOURNALD`, `HOST_METRICS`, `PROMETHEUS`,
`HTTP_JSON_METRICS`, `SQL_METRICS`, and `PLUGIN_METRICS`. It never accepts raw
collector documents, arbitrary executables, or shell commands.

On startup the Agent verifies and activates its last valid stored policy when
the server is unavailable. A newer remote policy is atomically checked before
it replaces the active pipeline; a failed candidate leaves the prior pipeline
running and reports `ROLLED_BACK`. Reverting policy requires a newly signed,
monotonically higher policy version rather than an unsigned local edit.

Telemetry leaves only through mutually authenticated DBPilot gRPC. Configure
the CA, Agent certificate, and Agent key from the bootstrap configuration;
the gateway authenticates the SPIFFE Agent identity in the client certificate.

## Spool and health behavior

Payloads are stored in CRC-protected segment files under the data directory;
bbolt stores only state, checkpoints, indexes, and deduplication metadata.
Accepted batches are removed only after the gateway acknowledgement. During an
outage, collectors continue and the exporter retries from the spool. Metrics
and ordinary logs may be evicted under the signed capacity limit; unacknowledged
audit logs are never silently discarded. Important health findings include
`AUDIT_SPOOL_FULL`, `AUDIT_SPOOL_IO_FAILURE`, `CORRUPT_SEGMENT`, and telemetry
permanent-rejection findings.

Upgrade by stopping the unit, replacing the binary, and starting it again;
the local spool and last known valid policy allow recovery. To roll back a
binary, restore the prior binary and restart the unit. Do not delete the data
directory unless intentionally discarding pending telemetry.

## Build and smoke evidence

Use an absolute Go 1.27.0 executable path:

```powershell
powershell -File .\scripts\build-linux.ps1 -OutputDirectory "$pwd\bin" -Version 0.1.0-test -GoBinary 'C:\absolute\path\to\go.exe'
```

The smoke commands to record on dedicated Linux VMs are:

```sh
dbpilot-agent --version
dbpilot-agent --config /etc/dbpilot/agent.yaml
systemctl restart dbpilot-agent
journalctl -u dbpilot-agent --since '5 minutes ago'
```

Run those commands on CentOS 7 amd64, Kylin V10 amd64, and Kylin V10 arm64
with a real mTLS test gateway and journald permissions. This Windows worktree
cannot record those Linux-specific systemd/journald results; release approval
requires attaching the three runner logs.

### Windows Docker/Kylin verification

Windows development can verify the Linux executable inside an approved Kylin
V10 Docker image. Build the amd64/arm64 artifacts first, then run
`scripts/verify-kylin-docker.ps1` with `-Image` set to the enterprise Kylin
image and the matching `-Architecture`. The script rejects missing Docker,
missing images, non-Kylin `/etc/os-release`, architecture mismatches, and
startup failures. It never substitutes a generic Linux image for Kylin.

This container check covers executable compatibility and bootstrap startup.
Systemd, journald ACLs, kernel metrics, eBPF, and real Kylin service behavior
must still be verified on Kylin V10 amd64/arm64 VM or bare-metal runners.
