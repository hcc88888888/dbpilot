# Kylin Docker verification

The repository does not publish or redistribute a Kylin base image. Use an
approved enterprise Kylin V10 image and pass its full image reference to
`verify-kylin-docker.ps1`. The image must expose `/etc/os-release` with a Kylin
identity and match the requested architecture.

Example from Windows PowerShell:

```powershell
$go = 'D:\path\to\go1.27.0.exe'
New-Item -ItemType Directory -Force .\bin | Out-Null
powershell -File ..\scripts\build-linux.ps1 `
  -OutputDirectory (Resolve-Path .\bin) `
  -Version 0.1.0-kylin `
  -GoBinary $go

powershell -File ..\scripts\verify-kylin-docker.ps1 `
  -Image registry.example.com/os/kylin:v10-amd64 `
  -Binary (Resolve-Path .\bin\dbpilot-agent-linux-amd64) `
  -Architecture amd64
```

If Docker Desktop is not on `PATH`, add
`-DockerBinary "$env:LOCALAPPDATA\Programs\DockerDesktop\resources\bin\docker.exe"`.

For arm64, use a Kylin V10 arm64 image and set `-Architecture arm64`. Docker
Desktop must have an engine capable of running the requested platform. If no
Kylin image is available locally, the script fails explicitly; do not replace
it with CentOS/Ubuntu and label the result as Kylin validation.

The script checks the image identity, CPU architecture, executable startup,
and `--version`. Full systemd/journald and kernel/eBPF checks still require a
Kylin V10 VM or bare-metal runner because containers do not provide a real
systemd host or Kylin kernel.
