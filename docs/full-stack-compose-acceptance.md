# Full-stack Compose acceptance

The full-stack verifier runs the production DBPilot control plane and Agent in
the approved Kylin V10 SP1 image. It proves browser OIDC/RBAC, Agent mTLS and
Heartbeat, telemetry persistence, the two-phase inspection command, immutable
reports, restart replay, rogue identity rejection, PostgreSQL state, and Agent
journal state.

## Prerequisites

- Windows Docker Desktop with Docker Compose v2 and an amd64 Linux runtime.
- Windows PowerShell 5.1 or PowerShell 7+, and Go 1.27.0.
- The exact private image
  `cr.kylinos.cn/kylin/kylin-server-platform:v10sp1` already available locally.
- Network access for the pinned public Go, PostgreSQL, Nginx, and Playwright
  images when they are not already cached.
- At least 6 GiB of free Docker memory for the builder and browser phases.

The verifier does not replace the private Kylin image with another Linux image
and does not log in to the enterprise registry. Pull or authorize the image
before starting the run.

Before creating services, the verifier performs one bounded Compose pull for
only `asset-builder`, `postgres`, and `frontend`. It never force-pulls the
private Kylin image. The Playwright runner image build and the clean Go asset
build have separate 30-minute deadlines; ordinary one-shot phases retain their
shorter five-minute deadline. Every subsequent Compose `up` uses
`--pull never`, so daemon-side image downloads cannot escape verifier process
ownership. Short Docker inspect/start/remove commands retain a 30-second
deadline.

## Run

From the repository root:

```powershell
powershell -NoProfile -File backend/scripts/verify-full-stack-compose.ps1 `
  -Image 'cr.kylinos.cn/kylin/kylin-server-platform:v10sp1' `
  -Architecture amd64 `
  -GoBinary 'C:\absolute\go.exe'
```

Each invocation creates a unique Compose project and ownership run label. It
records every discovered container ID, network ID, named or anonymous volume
name, its host temporary directory, and the Docker-assigned frontend loopback
port before proceeding.

A complete run emits these fixed milestones:

```text
OIDC acceptance passed
Agent mTLS communication passed
Host inspection browser acceptance passed
Control-plane restart and spool recovery passed
Rogue Agent rejection passed
Database and journal assertions passed
Full-stack cleanup audit passed
```

The host records the completed control-plane stop and start instants. The Agent
remains running through the bounded outage and reconnect check. The verifier
then stops the valid Agent before the fixture reads its spool replay evidence or
command journal.

## Failure artifacts and cleanup

Success retains no logs, screenshots, credentials, or generated binaries. On
failure only, the verifier copies bounded container log tails and Playwright's
already-redacted DOM, console, and screenshot attachments to the printed
`dbpilot-full-stack-failure-<run>` directory under the system temporary root.
Text is scrubbed again for Bearer tokens, JWTs, credential-bearing PostgreSQL
URLs, password/credential/token/secret assignments, and private-key blocks.
Secret and configuration volumes are never copied.

The `finally` path removes containers by recorded ID, then networks by recorded
ID and volumes by recorded name. Every resource is re-inspected immediately
before removal and must still carry both the exact verifier and run labels.
Cleanup never uses `docker compose down`, a name wildcard, Docker socket mount,
or any Docker prune command. A final ID and label audit must find zero runtime
resources, and the verifier's working directory must be absent. A similarly
named project is outside the ownership label and remains untouched.

If a run fails, start with the fixed error and the redacted failure directory.
An unavailable Kylin image is a prerequisite failure. A slow first run can be a
public-image pull or clean Go-module build; allow those exact operations to
finish rather than substituting tags. If cleanup reports a label mismatch, do
not delete the resource broadly: inspect its labels and resolve ownership
manually.

## Acceptance boundary

The fixture OIDC endpoint issues short-lived test tokens through an internal
bootstrap credential. The frontend consumes the narrow
`window.DBPILOT_GET_ACCESS_TOKEN` provider. This is not Authorization Code with
PKCE, refresh, logout, or browser session storage.

The frontend loopback endpoint and all container-to-container HTTP paths use the
ephemeral bootstrap CA. PostgreSQL is isolated on the internal Compose network
with TLS disabled. Production public trust distribution, PostgreSQL TLS,
external secret management, high availability, and Kylin VM or bare-metal
systemd/SELinux evidence remain separate release gates.

The current frontend remains native HTML/CSS/ES modules. PKCE and a possible
React/TypeScript/Vite migration are separate product changes because neither is
required to prove the current production API, Agent, persistence, and browser
workflow.

Normal pull-request CI runs Compose parsing and the fake-Docker lifecycle tests.
The live private-image job appears only as the explicit `run_full_stack` manual
workflow input and requires a prepared self-hosted Windows runner.
