# Runtime rollback

Rollback is generation-owned and fail closed. It never deletes arbitrary
strongSwan sockets or the whole scratch tree.

## CP7A unprivileged runtime

Normal stop:

```bash
scripts/stop_native_charon.sh --stop --cp7a-unprivileged
```

The script validates all of the following before signaling a live PID:

- state-file schema, owner, and mode;
- pinned executable path and SHA-256;
- process start-time digest, preventing PID reuse;
- VICI socket path, inode, and owning PID;
- canonical generation config/log paths.

It sends bounded `INT`, then `TERM`, then `KILL` only to the verified process.
If the PID is already gone, it removes stale files only when the executable
hash, socket inode, and absence of another socket owner still match. A second
stop is an idempotent success. Failed-start cleanup also waits for and reaps its
own child; if the child survives the bounded sequence, its config, log, and a
mode-600 `failed-start.owner` identity record are preserved.

Verification:

```bash
scripts/snapshot_network_state.sh --output <scratch>/after.json
scripts/assert_clean_teardown.sh \
  --before <scratch>/before.json \
  --after <scratch>/after.json
```

Required result: no native process, current state, compiled PID file, owned
VICI socket, synthetic route, production IKE port, or new utun; stable default
route, DNS, and Surge process. Global route-table hash equality is informational
because unrelated cloned/cache routes may change.

The state file is removed only after the generation directory is empty and
successfully removed. Unexpected files therefore make stop fail while retaining
the state needed for a safe retry. The final assertion also checks the fixed
socket path and all `generation-*` directories directly, so missing state cannot
hide orphan residue.

## Refusal cases

Stop refuses to signal or delete when it sees a wrong executable, changed
binary hash, mismatched start time, replaced socket inode, another socket owner,
symlink, path escape, wrong state mode/owner, or unknown state key. Resolve the
identity discrepancy first; do not use a broad `pkill`, `killall`, or recursive
scratch deletion.

An unowned historical socket may exist elsewhere in the scratch root. It is a
baseline artifact and is outside generation-owned cleanup.

## CP7B privileged window

The CP7B runner/stop command will be invoked through macOS native AppleScript
authorization after explicit approval. Its rollback uses the same identity
contract under root, followed by unprivileged before/after comparison. No
persistent LaunchDaemon, system extension, NetworkExtension, or system-prefix
install is created.

If Surge/default-route/DNS changes unexpectedly, stop the native generation
first and preserve value-free snapshots. Do not reload or reconfigure Surge
automatically. Any Surge recovery action is a new explicit user decision.

If automatic stop cannot prove ownership, the experiment pauses with the
state path, recorded PID, expected executable hash, and socket inode. Codex
must alert the user before requesting any manual intervention.
