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

Only CP7B preflight implementation is currently authorized. The commands in
this section describe the candidate rollback contract; they must not be run
until the user separately approves the finalized manifest hash and exact live
command.

The CP7B runner and stop entry points invoke a short-lived root worker through
macOS native AppleScript authorization. They do not use `sudo`, ask for a
password, create a LaunchDaemon, install a system extension/NetworkExtension,
or write a system prefix.

Normal stop after that second approval uses the same reviewed manifest hash as
the launch:

```bash
scripts/stop_cp7b_backend.sh \
  --execute-reviewed \
  --manifest-sha256 c5464052f21af585a348a3fced8d1b5cf4fa336f8128fd9e64acc10465add877
```

The root worker copies a reviewed emergency-stop script into the mode-700 CP7B
runtime root before starting `charon`. State schema 3 records checkpoint,
phase, attempt, generation, PID, target and launcher paths/hashes, process-start
digest, config path/hash, log path, gate/handshake paths, socket path/inode,
manifest hash, and emergency-stop path. Stop validates this identity before
signaling.

Before the worker starts, AppleScript protects the runtime parent and copies a
hash-bound root entry into a root-owned bootstrap directory. The root entry
copies and verifies the closure helper, takes every executable/dylib/plugin and
reviewed internal alias into a root-owned non-writable closure, then copies and
re-verifies the worker, remaining libraries, official Python VICI package, and
read-only probe. Root sources only the verified bootstrap copy. Normal cleanup
removes the bootstrap directory and completed attempt ledger as well as the
generation state. The dedicated runtime directory stays root-owned throughout
the privileged window and is returned to the desktop user only when its top
level is exactly the reviewed closure baseline. A failed first launch keeps the
root-owned attempt ledger and closure for the one separately approved retry.

The signal sequence is bounded INT, TERM, then KILL. It targets only the
recorded process whose executable, hash, start identity, and VICI socket inode
still match. Cleanup is generation-owned and removes:

- the CP7B `charon` process;
- VICI socket and compiled scratch PID file;
- config and raw log;
- state, gated-launch FIFO/handshake, and temporary state files;
- root-owned emergency-stop copy;
- root-owned bootstrap bundle and completed-window attempt ledger;
- the empty generation directory.

The raw kernel log may observe PF_KEY events belonging to the concurrently
running vendor tunnel. It never leaves the protected runtime directory and is
deleted after a value-free failure category is extracted. No raw SAD, SPD,
route, endpoint, credential, or packet value is copied to the retained result.

After normal stop, verify the value-free result and filesystem directly:

```bash
scripts/assert_cp7b_teardown.sh --result <scratch-result-json>
```

The assertion requires zero process, socket, PID, state, emergency-stop copy,
bootstrap, ledger, and generation residue, plus an intact UID-502 closure
baseline. It also requires the retained result to bind the approved manifest,
source commit, and config hash and to prove:

- zero native UDP descriptors and no server traffic;
- no credential read, VICI initiate, or install operation;
- global SAD and SPD hashes unchanged;
- `net.inet.ipsec.esp_port` unchanged;
- default route, DNS, and utun inventory unchanged;
- PowerVPN and Surge process counts and start/command identities unchanged;
- read-only Surge environment and DNS probes passed before and after.

The `socket-dynamic` profile is central to rollback safety. Unlike the retired
`socket-default` proposal, it opens no UDP socket without a send, so CP7B must
never need to restore the global ESP port. If the ESP-port hash changes at any
point, cleanup still runs but the window fails; the runner must not guess and
write a previous sysctl value while PowerVPN is active.

If Surge/default-route/DNS changes unexpectedly, stop the native generation
first and preserve value-free snapshots. Do not reload or reconfigure Surge
automatically. Any Surge recovery action is a new explicit user decision.

If automatic stop cannot prove ownership, the experiment pauses with the
state path, recorded PID, expected executable hash, and socket inode. Codex
must alert the user before requesting any manual intervention.

If the manifest, source commit, config bytes, closure tree, binary, plugin,
launcher, runner, snapshot, stop, authorizer, or oracle hash differs from the
reviewed manifest, launch and
stop wrappers fail closed before privilege use. Do not bypass this with broad
`pkill`, `killall`, recursive deletion, `setkey -F`, `setkey -FP`, a Surge
reload, or an unreviewed sysctl restore.
