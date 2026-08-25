# Kylin Docker validation record

## Windows Docker Desktop run

- Date: 2026-08-26
- Image: `cr.kylinos.cn/kylin/kylin-server-platform:v10sp1`
- Image OS: Kylin Linux Advanced Server V10 (Tercel)
- Image architecture: `amd64`
- Container architecture: `x86_64`
- Agent artifact: `dbpilot-agent-linux-amd64`
- Agent version: `0.1.0-test`
- Result: PASS

Command:

```powershell
powershell -File .\backend\scripts\verify-kylin-docker.ps1 `
  -DockerBinary "$env:LOCALAPPDATA\Programs\DockerDesktop\resources\bin\docker.exe" `
  -Image cr.kylinos.cn/kylin/kylin-server-platform:v10sp1 `
  -Binary (Resolve-Path .\backend\bin\dbpilot-agent-linux-amd64) `
  -Architecture amd64
```

Observed output included:

```text
0.1.0-test
Kylin validation passed: ID=kylin VERSION=V10 ARCH=x86_64
```

This validates executable compatibility and bootstrap startup inside Kylin V10.
Systemd, journald ACL, kernel metrics, eBPF, and arm64 still require matching
Kylin V10 runners/images.
