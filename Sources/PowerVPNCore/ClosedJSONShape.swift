import Foundation

enum ClosedJSONShape {
  static func hasExactObject(_ value: Any?, keys: Set<String>) -> Bool {
    guard let object = value as? [String: Any] else { return false }
    return Set(object.keys) == keys
  }

  static func hasOptionalExactObject(
    _ root: [String: Any],
    key: String,
    keys: Set<String>
  ) -> Bool {
    guard let value = root[key] else { return true }
    return hasExactObject(value, keys: keys)
  }

  static func hasOnlyAllowedKeys(
    _ object: [String: Any],
    required: Set<String>,
    optional: Set<String>
  ) -> Bool {
    let keys = Set(object.keys)
    return required.isSubset(of: keys) && keys.isSubset(of: required.union(optional))
  }
}
