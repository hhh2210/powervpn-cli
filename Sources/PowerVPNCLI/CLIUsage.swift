func printCLIUsage() {
  print(
    """
    Usage: powervpn <command> [options]

      up <target>            Start a reusable background THU session
      down                   Stop the reusable session and verify cleanup
      status [--json]        Show connected/disconnected product state
      ssh <target> [-- command]
                             Open ephemeral SSH and clean up afterward
      doctor [--json]        Show readiness and the first actionable blocker
      debug help             Show development and compatibility commands

    Options:
      --json                 Emit JSON
    """)
}

func printCLIDebugUsage() {
  print(
    """
    PowerVPN development and compatibility commands:

      debug status [--json]  Show raw GUI/helper/crash/tunnel state
      debug doctor --json    Show the legacy readiness report
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
      portal dry-run --resource-display-name <exact> --ssh-target <key> --json
                             Validate one Portal snapshot and logout without helper/SSH
      doctor --json          Show product readiness and the first blocker
      helper status [--probe] --json
                             Show passive helper state; --probe performs one bounded get_version
      resources --json       List selectable authorized resources, if available
      snapshot --dry-run --json
                             Check authorized snapshot completeness without serializing it
      m2 connect-once --resource-display-name <exact> --ssh-target <key> --json
                             Run one M2 connect/prove/cleanup transaction with TTY code approval
      m2 connect-once --resource-display-name <exact> --ssh-target <key> --non-interactive --json
                             Run one M2 transaction without TTY approval; portal credentials
                             come from ~/.config/powervpn/credentials.env (0600) or
                             POWERVPN_PORTAL_CREDENTIALS
      proxy ssh --resource-display-name <exact> --ssh-target <key> <numeric-ipv4> <port> [--non-interactive]
                             Open one foreground nc stream through an approved tunnel
      proxy serve --resource-display-name <exact> --ssh-target <key>
                  [--listen-port <1-65535>] [--non-interactive] [--json]
                             Run foreground OpenSSH dynamic forwarding for other TCP apps;
                             Remote-SSH continues to use its normal route or ProxyJump
      targets config         ~/.config/powervpn/targets.json (regular file, mode 0600);
                             --ssh-target resolves an exact key from its targets object
    """)
}
