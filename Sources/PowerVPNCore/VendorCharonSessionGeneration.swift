package enum VendorCharonSessionGenerationValidator {
  /// The non-reconnecting session supplies peer continuity; launchd supplies
  /// the exact cold-to-single-running generation transition.
  package static func validate(
    before: VendorHelperGenerationSnapshot,
    current: VendorHelperGenerationSnapshot
  ) -> Bool {
    guard before.exactInactive, current.exactRunning,
      let beforeRuns = before.runs, beforeRuns < Int.max
    else { return false }
    return current.runs == beforeRuns + 1
  }
}
