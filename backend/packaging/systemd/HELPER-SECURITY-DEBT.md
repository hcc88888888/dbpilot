# Local helper security debt

| Affected module | Trigger | Functional impact | Severity | Remediation stage |
| --- | --- | --- | --- | --- |
| CentOS 7 proc-helper systemd profile | systemd 219 ignores newer sandbox directives such as `ProtectKernelModules`, `RestrictNamespaces`, `MemoryDenyWriteExecute`, or parts of system-call grouping | Native discovery remains functional and the main Agent stays capability-free; the root legacy helper has a weaker sandbox around its fixed allowlisted protocol | Medium security, non-blocking for current functionality | Task 17 / mandatory pre-production CentOS 7 VM verification; add a systemd-219-compatible seccomp/MAC policy and reject installation if the effective unit exceeds the documented capability set |
| Kylin SELinux confinement | Production enables a stricter custom SELinux policy than the validation image | No current functional impact; systemd syscall denial and protocol filtering remain active, but helper-to-helper procfs denial is not independently expressed as a DBPilot SELinux type transition | Medium defense-in-depth | Pre-production Kylin hardening; ship and verify dedicated `dbpilot_proc_t` and `dbpilot_docker_t` domains before treating helper compromise containment as complete |

Core isolation is not deferred: the main Agent has empty effective, ambient and
bounding capability sets; only `dbpilot-docker` belongs to the Docker group;
the proc-helper and Docker-helper use distinct identities and fixed private UDS
protocols with exact Agent `SO_PEERCRED` checks.
