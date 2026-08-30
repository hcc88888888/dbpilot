# Restricted Docker discovery opt-in

Docker discovery is a local-administrator opt-in and must be installed before
the Agent enrolls. DBPilot Server cannot install this unit, change Docker group
membership, or grant Docker Socket access remotely.

1. Create three distinct identities: `dbpilot` for the main Agent,
   `dbpilot-proc` for bounded procfs inspection, and `dbpilot-docker` for this
   helper.
2. If local policy permits Docker discovery, add only `dbpilot-docker` to the
   Docker Socket group. Never add `dbpilot` or `dbpilot-proc` to that group.
3. Copy `dbpilot-docker-discovery.env.example` to
   `/etc/dbpilot/docker-discovery.env`; set the exact numeric Agent UID/GID and
   the label keys approved by local policy.
4. Install and enable `dbpilot-docker-discovery.socket` and
   `dbpilot-docker-discovery.service`, then confirm
   `/run/dbpilot-agent/docker-discovery.sock` is an AF_UNIX socket with mode
   `0600` owned by the Agent identity. systemd creates the client socket; the
   helper stays under the distinct `dbpilot-docker` UID and validates the
   connecting main Agent's exact primary UID/GID with `SO_PEERCRED`.
5. Enable `docker_discovery` in the local Agent configuration and enroll the
   host. If the helper is absent or unhealthy, native discovery continues and
   the capability is reported as `docker_discovery_unavailable`.

The helper exposes only bounded container inventory DTOs. It never exposes
environment variables, raw Docker inspect payloads, mounts, arbitrary labels,
or unredacted commands. It supports no container mutation, exec, logs, archive,
attach, or stats operation.
