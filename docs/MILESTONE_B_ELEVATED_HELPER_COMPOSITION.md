# Milestone B — Elevated Helper Composition

This slice makes the privileged replacement plan derive installation authority from the already verified `AuthorizedUpdate` result.

## Locked boundary

`install_root` and executable identity are authority-bearing values. They must come from the Agent request + Digital update policy + BKE install-target policy composition gate, never from caller-selected helper arguments.

The helper may still own ephemeral execution state such as staging root, backup root, transaction state, readiness marker, and bounded startup behavior. Those paths are independently validated for existence, separation, containment, and overlap.

## This slice

- adds `compose_helper_plan(...)`;
- derives `HelperPlan.install_root` from `AuthorizedUpdate.install_root`;
- derives `HelperPlan.executable` from the authorized entry point;
- validates the exact staged entry point exists;
- rejects traversal, cross-root entry points, and overlapping helper roots;
- keeps the existing transactional replace/restart/rollback implementation unchanged.

## Not yet claimed

The legacy generic helper CLI still exists for compatibility/testing and is not promoted to production update authority by this slice. Production elevation must next be wired so it receives and verifies the signed authority inputs, calls `compose_authority(...)`, then `compose_helper_plan(...)`, and only then invokes replacement. Native UAC/process/restart certification remains a separate release gate.
