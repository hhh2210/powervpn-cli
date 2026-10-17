import Foundation

/// Runs blocking test code on its own thread instead of the cooperative pool.
/// Fixtures that intentionally block (a held borrow, a poll loop on a PTY)
/// would otherwise occupy a pool thread the code under test needs, which
/// starves on small CI runners.
func onDedicatedThread<T: Sendable>(
  _ body: @escaping @Sendable () throws -> T
) async throws -> T {
  try await withCheckedThrowingContinuation { continuation in
    Thread { continuation.resume(with: Result { try body() }) }.start()
  }
}

func onDedicatedThread(_ body: @escaping @Sendable () -> Void) async {
  await withCheckedContinuation { continuation in
    Thread {
      body()
      continuation.resume()
    }.start()
  }
}
