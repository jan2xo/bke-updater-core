from __future__ import annotations

import argparse
from pathlib import Path
from typing import Sequence

from .privileged_entrypoint import execute_privileged_update
from .trusted_runtime import TrustedRuntimePaths, load_privileged_execution_config
from .windows_elevation import PrivilegedInvocationFiles, read_json_document, validate_invocation_files


class PrivilegedCliError(RuntimeError):
    pass


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="bke-updater-helper")
    parser.add_argument("--privileged-update", action="store_true", required=True)
    parser.add_argument("--runtime-root", required=True)
    parser.add_argument("--request", required=True)
    parser.add_argument("--update-policy", required=True)
    parser.add_argument("--target-policy", required=True)
    parser.add_argument("--artifact", required=True)
    parser.add_argument("--staged-root", required=True)
    parser.add_argument("--backup-root", required=True)
    parser.add_argument("--transaction-root")
    parser.add_argument("--transaction-id")
    parser.add_argument("--wait-pid", type=int)
    parser.add_argument("--launch-arg", action="append", default=[])
    parser.add_argument("--ready-marker")
    parser.add_argument("--startup-timeout", type=float, default=10.0)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    runtime_root = Path(args.runtime_root)
    files = validate_invocation_files(
        PrivilegedInvocationFiles(
            runtime_root=runtime_root,
            request_document=Path(args.request),
            update_policy_document=Path(args.update_policy),
            target_policy_document=Path(args.target_policy),
            artifact_path=Path(args.artifact),
            staged_root=Path(args.staged_root),
            backup_root=Path(args.backup_root),
            transaction_root=Path(args.transaction_root) if args.transaction_root else None,
        )
    )
    config = load_privileged_execution_config(TrustedRuntimePaths.under(files.runtime_root))
    return execute_privileged_update(
        config=config,
        request_document=read_json_document(files.request_document),
        update_policy_document=read_json_document(files.update_policy_document),
        target_policy_document=read_json_document(files.target_policy_document),
        artifact_path=files.artifact_path,
        staged_root=files.staged_root,
        backup_root=files.backup_root,
        transaction_root=files.transaction_root,
        transaction_id=args.transaction_id,
        wait_pid=args.wait_pid,
        launch_args=tuple(args.launch_arg),
        ready_marker=args.ready_marker,
        startup_timeout=args.startup_timeout,
    )


if __name__ == "__main__":
    raise SystemExit(main())
