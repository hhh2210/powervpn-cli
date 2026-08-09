on run argv
  if (count of argv) is not 2 then error "CP7B authorization requires an action and manifest hash" number 64

  set actionName to item 1 of argv
  set manifestSHA to item 2 of argv
  if actionName is not "--run-reviewed" and actionName is not "--stop-reviewed" then
    error "Unsupported CP7B authorization action" number 64
  end if

  set rootEntry to "/Users/larry_1/Opensource/powervpn-cli/scripts/libexec/cp7b_root_entry.sh"
  set runtimeRoot to "/Users/larry_1/scratch-data/powervpn-strongswan/runtime-6.0.7-cp7b"
  set expectedEntrySHA to "565b0aba9a5f47b1a910698db1461a8c2c1e8498b90d6de7a03d1568c3976f6c"
  set expectedEmergencySHA to "fb82025b81727851539d4ed6691ba627bb0ac239ed0dacc8445271fa2aa27df1"
  set runtimeGuard to "set -eu; umask 077; runtime=" & quoted form of runtimeRoot & "; " & ¬
    "[ -d \"$runtime\" ] && [ ! -L \"$runtime\" ] && [ \"$(/usr/bin/stat -f '%Lp' \"$runtime\")\" = 700 ] || { echo 'error: CP7B runtime root identity changed' >&2; exit 70; }; " & ¬
    "owner=$(/usr/bin/stat -f '%u' \"$runtime\"); case \"$owner\" in 0|502) ;; *) echo 'error: CP7B runtime root owner changed' >&2; exit 70;; esac; closure=\"$runtime/closure\"; ledger=\"$runtime/pfkey-attempt-ledger\"; " & ¬
    "[ -d \"$closure\" ] && [ ! -L \"$closure\" ] || { echo 'error: CP7B closure baseline is missing' >&2; exit 70; }; "
  set bootstrapGuard to "if [ \"$owner\" -eq 502 ]; then " & ¬
    "[ \"$(/usr/bin/stat -f '%u:%g:%Lp' \"$runtime\")\" = 502:20:700 ] && [ \"$(/usr/bin/stat -f '%u:%g' \"$closure\")\" = 502:20 ] && [ \"$(/usr/bin/find \"$runtime\" -mindepth 1 -maxdepth 1 -print | /usr/bin/awk 'END { print NR + 0 }')\" -eq 1 ] || { echo 'error: CP7B user-owned closure baseline is ambiguous' >&2; exit 70; }; " & ¬
    "else [ \"$(/usr/bin/stat -f '%u:%g:%Lp' \"$runtime\")\" = 0:0:700 ] && [ \"$(/usr/bin/stat -f '%u:%g' \"$closure\")\" = 0:0 ] && [ -z \"$(/usr/bin/find \"$runtime\" -mindepth 1 -maxdepth 1 ! -path \"$closure\" ! -path \"$ledger\" -print -quit)\" ] || { echo 'error: CP7B root-owned retry state is ambiguous' >&2; exit 70; }; " & ¬
    "if [ -e \"$ledger\" ]; then [ -f \"$ledger\" ] && [ ! -L \"$ledger\" ] && [ \"$(/usr/bin/stat -f '%u:%g:%Lp' \"$ledger\")\" = 0:0:600 ] || { echo 'error: CP7B retry ledger identity changed' >&2; exit 70; }; fi; fi; "
  set bootstrapCommand to "[ \"$owner\" -eq 0 ] || /usr/sbin/chown 0:0 \"$runtime\"; [ \"$(/usr/bin/stat -f '%u:%g:%Lp' \"$runtime\")\" = 0:0:700 ] || { echo 'error: CP7B runtime root takeover failed' >&2; exit 70; }; bootstrap=\"$runtime/.bootstrap-$$\"; " & ¬
    "cleanup() { /bin/rm -f -- \"$bootstrap/root-entry.sh\"; /bin/rmdir \"$bootstrap\" 2>/dev/null || true; if [ \"$(/usr/bin/find \"$runtime\" -mindepth 1 -maxdepth 1 -print | /usr/bin/awk 'END { print NR + 0 }')\" -eq 1 ] && [ -d \"$closure\" ] && [ ! -L \"$closure\" ] && [ \"$(/usr/bin/stat -f '%u:%g' \"$closure\")\" = 502:20 ]; then /usr/sbin/chown 502:20 \"$runtime\"; /bin/chmod 700 \"$runtime\"; fi; }; trap cleanup EXIT HUP INT TERM; " & ¬
    "/bin/mkdir \"$bootstrap\"; /bin/cp " & quoted form of rootEntry & " \"$bootstrap/root-entry.sh\"; /usr/sbin/chown 0:0 \"$bootstrap/root-entry.sh\"; /bin/chmod 700 \"$bootstrap/root-entry.sh\"; " & ¬
    "actual=$(/usr/bin/shasum -a 256 \"$bootstrap/root-entry.sh\" | /usr/bin/awk '{print $1}'); " & ¬
    "[ \"$actual\" = " & quoted form of expectedEntrySHA & " ] || { echo 'error: reviewed CP7B root entry hash mismatch' >&2; exit 70; }; " & ¬
    "exec \"$bootstrap/root-entry.sh\" " & quoted form of actionName & " " & quoted form of manifestSHA

  if actionName is "--stop-reviewed" then
    set directStop to "state=\"$runtime/current.state\"; emergency=\"$runtime/emergency-stop\"; if [ -e \"$state\" ]; then " & ¬
      "[ \"$owner\" -eq 0 ] && [ -f \"$emergency\" ] && [ ! -L \"$emergency\" ] && [ \"$(/usr/bin/stat -f '%u' \"$emergency\")\" -eq 0 ] && [ \"$(/usr/bin/stat -f '%Lp' \"$emergency\")\" = 700 ] || { echo 'error: CP7B emergency stop identity changed' >&2; exit 70; }; " & ¬
      "actual=$(/usr/bin/shasum -a 256 \"$emergency\" | /usr/bin/awk '{print $1}'); [ \"$actual\" = " & quoted form of expectedEmergencySHA & " ] || { echo 'error: CP7B emergency stop hash changed' >&2; exit 70; }; \"$emergency\" --stop >/dev/null; owner=$(/usr/bin/stat -f '%u' \"$runtime\"); fi; "
    set shellCommand to runtimeGuard & directStop & bootstrapGuard & bootstrapCommand
  else
    set shellCommand to runtimeGuard & bootstrapGuard & bootstrapCommand
  end if

  return do shell script shellCommand with administrator privileges
end run
