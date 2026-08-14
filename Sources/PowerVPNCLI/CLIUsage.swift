func printCLIUsage() {
  print(
    """
    Usage: powervpn <command> [options]

      status                 Show GUI, helper, crash, and tunnel state
      probe                  Blocked until an explicitly approved M2 transaction
      diagnose              Blocked until a local-only M3 diagnostic exists
      oracle [inventory]     Read-only vendor helper and protocol inventory
      oracle correlate <value-free-trace.json>
                             Validate metadata-only control/XPC correlation
      spec validate-redacted <path>
                             Validate a commit-safe redacted TunnelSpec fixture
      spec vici-dry-run <path>
                             Build and hash a pure-Swift VICI load-conn payload
      vici version --socket <path> [--timeout-ms N]
                             Run a value-free version request against charon
      vici cp7a-smoke --socket <path> [--timeout-ms N]
                             Run bounded synthetic load/list/unload over VICI
      xpc get-version [--timeout-ms N]
                             Read the installed charon helper version over exact XPC
      login                  Run the sealed username/password portal transaction
      portal dry-run --resource-display-name <exact> --ssh-target <thu21|thu52> --json
                             Validate one Portal snapshot and logout without helper/SSH
      doctor --json          Show product readiness and the first blocker
      helper status [--probe] --json
                             Show passive helper state; --probe performs one bounded get_version
      resources --json       List selectable authorized resources, if available
      snapshot --dry-run --json
                             Check authorized snapshot completeness without serializing it
      m2 connect-once --resource-display-name <exact> --ssh-target <thu21|thu52> --json
                             Run one approved M2 connect/prove/cleanup transaction

    Options:
      --json                 Emit JSON
    """)
}
