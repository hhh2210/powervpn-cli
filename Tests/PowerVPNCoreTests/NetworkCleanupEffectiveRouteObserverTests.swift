import Foundation
import Testing

@testable import PowerVPNCore

@Suite struct NetworkCleanupEffectiveRouteObserverTests {
  private let target: UInt32 = 0x0A01_0209

  @Test func commandUsesOnlyTheCanonicalNumericTarget() {
    let request = NetworkCleanupCommand.effectiveRoute(targetIPv4: target).request

    #expect(request.executable == "/sbin/route")
    #expect(request.arguments == ["-n", "get", "10.1.2.9"])
    #expect(request.timeoutMilliseconds == 2_000)
    #expect(request.stdoutLimitBytes == 65_536)
  }

  @Test func matcherCaptureObservesTheEffectiveSelectedBinding() async {
    let matcher = selectedMatcher()
    let command = matcher.effectiveRouteCommand
    var responses = networkCleanupSuccessfulResponses()
    responses[.ipv4Routes] = [
      networkCleanupSuccess(
        "Routing tables\nInternet:\nDestination Gateway Flags Netif Expire\n"
          + "default 192.0.2.1 UGScg en0\n10.1.2/24 link#9 UGScI utun9\n")
    ]
    responses[command] = [networkCleanupSuccess(effectiveRouteFixture())]
    let runner = FixtureNetworkCleanupRunner(responses)

    let snapshot = await InstalledNetworkCleanupObserver(runner: runner).capture(
      window: NetworkCleanupCaptureWindow(keyData: Data(repeating: 9, count: 32)),
      selectedRoutes: matcher
    )

    #expect(snapshot.complete)
    #expect(snapshot.ipv4Routes.effectiveSelectedRoute?.isObserved == true)
    let token = snapshot.ipv4Routes.effectiveSelectedRoute?.selectedRouteToken
    #expect(token != nil)
    #expect(token.map(snapshot.ipv4Routes.selectedRouteTokens.contains) == true)
    #expect(
      runner.observedCommands == [
        .helperGeneration, .surgeProcesses, .defaultRoute, .dns, .interfaces,
        .ipv4Routes, command, .ipv6Routes, .surgeProcesses, .helperGeneration,
      ])
  }

  @Test func commandAndParserFailuresMakeMatcherCaptureIncomplete() async {
    let matcher = selectedMatcher()
    let command = matcher.effectiveRouteCommand
    var commandFailure = networkCleanupSuccessfulResponses()
    commandFailure[command] = [.immediate(.launchFailed)]
    let failed = await InstalledNetworkCleanupObserver(
      runner: FixtureNetworkCleanupRunner(commandFailure)
    ).capture(window: NetworkCleanupCaptureWindow(), selectedRoutes: matcher)

    var malformed = networkCleanupSuccessfulResponses()
    malformed[command] = [
      networkCleanupSuccess("route to: 10.1.2.9\ndestination: 10.1.2.0\n")
    ]
    let rejected = await InstalledNetworkCleanupObserver(
      runner: FixtureNetworkCleanupRunner(malformed)
    ).capture(window: NetworkCleanupCaptureWindow(), selectedRoutes: matcher)

    #expect(!failed.complete)
    #expect(failed.ipv4Routes.effectiveSelectedRoute?.state == .commandFailed)
    #expect(!rejected.complete)
    #expect(rejected.ipv4Routes.effectiveSelectedRoute?.state == .invalidOutput)
  }

  @Test func directHostRouteMayOmitMaskAndGatewayButMustResolveUniquely() throws {
    let matcher = selectedMatcher(
      routes: [(network: target, prefix: 32)]
    )
    let routes = try parsedRoutes(["10.1.2.9 link#1 UH lo0"])
    let output = Data(
      "route to: 10.1.2.9\ndestination: 10.1.2.9\ninterface: lo0\nflags: <UP,HOST>\n"
        .utf8
    )
    let effective = try NetworkCleanupEffectiveRouteCanonicalizer.canonicalize(
      output,
      matcher: matcher,
      routes: routes
    )

    #expect(effective.selectedRouteToken == matcher.matches(routes).first)
  }

  @Test func gatewaylessProjectionRejectsMultipleTableCandidates() throws {
    let matcher = selectedMatcher(
      routes: [(network: target, prefix: 32)]
    )
    let routes = try parsedRoutes([
      "10.1.2.9 link#1 UH lo0", "10.1.2.9 link#2 UH lo0",
    ])
    let output = Data(
      "route to: 10.1.2.9\ndestination: 10.1.2.9\ninterface: lo0\nflags: <UP,HOST>\n"
        .utf8
    )

    #expect(throws: NetworkCleanupCanonicalizationError.invalidShape) {
      try NetworkCleanupEffectiveRouteCanonicalizer.canonicalize(
        output,
        matcher: matcher,
        routes: routes
      )
    }
  }

  @Test func projectionRejectsOutputForAnotherTarget() throws {
    let matcher = selectedMatcher()
    #expect(throws: NetworkCleanupCanonicalizationError.invalidShape) {
      try NetworkCleanupEffectiveRouteCanonicalizer.canonicalize(
        Data(effectiveRouteFixture().replacingOccurrences(of: "10.1.2.9", with: "10.1.2.10").utf8),
        matcher: matcher,
        routes: try parsedRoutes(["10.1.2/24 link#9 UGScI utun9"])
      )
    }
  }

  private func selectedMatcher(
    routes: [(network: UInt32, prefix: UInt8)] = [(network: 0x0A01_0200, prefix: 24)]
  ) -> VendorCharonSelectedRouteMatcher {
    VendorCharonSelectedRouteMatcher(
      keyData: Data(repeating: 7, count: 32),
      routes: routes,
      requiredTargetIPv4: target
    )
  }

  private func effectiveRouteFixture() -> String {
    """
    route to: 10.1.2.9
    destination: 10.1.2.0
    mask: 255.255.255.0
    gateway: link#9
    interface: utun9
    flags: <UP,GATEWAY,DONE,STATIC>
    """
  }

  private func parsedRoutes(_ rows: [String]) throws -> [NetworkCanonicalRoute] {
    let table =
      "Routing tables\nInternet:\nDestination Gateway Flags Netif Expire\n"
      + rows.joined(separator: "\n") + "\n"
    return try NetworkRouteCanonicalizer.parse(Data(table.utf8), family: .inet)
  }
}
