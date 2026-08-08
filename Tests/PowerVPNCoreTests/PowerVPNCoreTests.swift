import Foundation
import Testing

@testable import PowerVPNCore

@Test func parsesHelperCrashState() {
  let output = """
        state = running
        runs = 10
        successive crashes = 9
        pid = 97150
        last terminating signal = Illegal instruction: 4
    """
  let state = HelperOutputParser.parse(output)
  #expect(state.isRunning)
  #expect(state.pid == 97150)
  #expect(state.runs == 10)
  #expect(state.successiveCrashes == 9)
  #expect(state.lastTerminatingSignal == "Illegal instruction: 4")
}

@Test func classifiesSSHBanner() {
  let (status, detail) = SSHBannerClassifier.classify(Data("SSH-2.0-OpenSSH_9.9\r\n".utf8))
  #expect(status == .healthy)
  #expect(detail == "SSH-2.0-OpenSSH_9.9")
}

@Test func detectsStaleAuthenticationAfterEstablishedTunnel() {
  let log = """
        CHILD_SA ncv1 established
        invalid HASH_V1 payload length, decryption failed?
        sending retransmit 5
        giving up after 5 retransmits
    """
  #expect(TunnelLogAnalyzer.analyze(log).health == .staleAuthentication)
}

@Test func detectsRecoveryAfterStaleAuthentication() {
  let log = """
        invalid HASH_V1 payload length, decryption failed?
        giving up after 5 retransmits
        CHILD_SA ncv1 established
    """
  #expect(TunnelLogAnalyzer.analyze(log).health == .healthy)
}

@Test func commandRunnerDrainsOutputLargerThanPipeBuffer() throws {
  let output = try CommandRunner().run("/usr/bin/jot", ["20000"])
  #expect(output.hasPrefix("1\n2\n"))
  #expect(output.hasSuffix("20000\n"))
}
