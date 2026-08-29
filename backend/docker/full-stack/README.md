# Full-stack Compose topology

This directory defines the isolated DBPilot full-stack acceptance topology. It builds the production control-plane and Agent binaries plus the acceptance fixture with `golang:1.27.0-bookworm`, then runs DBPilot processes in the approved Kylin V10 SP1 amd64 image. PostgreSQL, OIDC, control-plane HTTP/gRPC, and Agent traffic remain on the internal `acceptance` network. Only Nginx publishes a Docker-assigned port on `127.0.0.1`.

The bootstrap service generates ephemeral material at `/acceptance`, then copies configuration, `0600` secrets, and state into separate named volumes owned by numeric UID/GID `10001:10001`. Runtime source, binaries, configuration, and secrets are mounted read-only. The control plane writes only its Artifact volume; the Agent writes only its data volume. PostgreSQL uses tmpfs rather than persistent storage.

The `faults` profile contains the two expected-failure rogue Agent services. The `assertions` profile contains the fixture database assertion service. The repository-level verifier introduced by the later orchestration task owns the unique Compose project and run labels, supplies the phase assertion state, records exact resource IDs, and performs cleanup.

This environment is acceptance-only. Loopback browser HTTP, internal PostgreSQL without TLS, fixture OIDC token issuance, containerized Kylin, and a single control plane/Agent are not production deployment guidance. It does not replace Authorization Code with PKCE, PostgreSQL TLS, external secret management, high availability, load/soak testing, or Kylin VM/bare-metal systemd, journald, kernel, network, and SELinux release evidence.
