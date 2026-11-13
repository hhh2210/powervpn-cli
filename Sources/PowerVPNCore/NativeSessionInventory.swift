import Foundation

/// Every IKE SA, connection and shared key charon holds, by name.
/// Throws when any of the three lists cannot be read: an unreadable list is
/// not an empty one.
package func nativeSessionNames(_ session: VICISession) throws -> Set<String> {
  var names = Set<String>()
  let sas = try session.streamedRequest(command: "list-sas", event: "list-sa")
  for ike in NativeIKESummary.parse(sas.events) { names.insert(ike.name) }
  for (command, key) in [("get-conns", "conns"), ("get-shared", "keys")] {
    let result = try session.request(command: command)
    guard
      let element = result.message.elements.first(where: {
        if case .list(key, _) = $0 { return true }
        return false
      }), case .list(_, let values) = element
    else { throw VICISessionError.commandFailed(command) }
    for value in values { names.insert(String(decoding: value, as: UTF8.self)) }
  }
  return names
}
