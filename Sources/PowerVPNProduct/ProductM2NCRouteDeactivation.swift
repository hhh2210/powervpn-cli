import PowerVPNCore

extension ProductM2CleanupRunner {
  func deactivateSelectedNCRoutes(
    _ coldGeneration: VendorHelperGenerationSnapshot,
    _ authority: ProductM2ControlCleanupAuthority,
    _ deadlines: ProductM2CleanupDeadlines
  ) async -> ProductM2ControlReceipt {
    guard authority.startReceipt.transportAcknowledged,
      authority.routeActivation.requestSent,
      let lease = authority.lease
    else {
      return .unsent(.notAttempted)
    }
    guard
      let operationDeadline = availableControlDeadline(
        deadlines.controlCleanup,
        reportDeadline: deadlines.report
      ),
      let timeout = operationDeadline.remainingMilliseconds(cappedAt: 1_000)
    else {
      return .unsent(.timeout)
    }
    let observe = dependencies.observeGeneration
    return await Task.detached {
      await lease.setSelectedNCEnabled(
        false,
        timeoutMilliseconds: timeout,
        peerGenerationValidator: {
          ProductM2GenerationFence.validatesReply(
            before: coldGeneration,
            current: await observe(operationDeadline)
          )
        }
      )
    }.value
  }
}
