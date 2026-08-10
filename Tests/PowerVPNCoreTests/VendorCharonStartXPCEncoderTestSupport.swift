import Foundation
@preconcurrency import XPC

@testable import PowerVPNCore

enum EncoderTestError: Error {
  case missingSnapshot
  case missingValue
  case wrongType
}

final class EraseRecorder: @unchecked Sendable {
  private let lock = NSLock()
  private var observations = 0
  private var zero = true

  func observe(_ bytes: UnsafeRawBufferPointer) {
    lock.withLock {
      observations += 1
      zero = zero && bytes.allSatisfy { $0 == 0 }
    }
  }

  var count: Int { lock.withLock { observations } }
  var allZero: Bool { lock.withLock { zero } }
}

final class InsertionRecorder: @unchecked Sendable {
  private let lock = NSLock()
  private var observations: [VendorCharonStartXPCScope: [VendorCharonStartField]] = [:]

  func observe(_ scope: VendorCharonStartXPCScope, _ field: VendorCharonStartField) {
    lock.withLock { observations[scope, default: []].append(field) }
  }

  func fields(in scope: VendorCharonStartXPCScope) -> [VendorCharonStartField] {
    lock.withLock { observations[scope, default: []] }
  }
}

func keys(_ dictionary: xpc_object_t) -> [String] {
  var result: [String] = []
  xpc_dictionary_apply(dictionary) { key, _ in
    result.append(String(cString: key))
    return true
  }
  return result
}

func hasExactKeys(_ dictionary: xpc_object_t, _ expected: [String]) -> Bool {
  let actual = keys(dictionary)
  return actual.count == expected.count && Set(actual) == Set(expected)
}

func dictionary(_ parent: xpc_object_t, _ key: String) throws -> xpc_object_t {
  let value = try requiredValue(parent, key)
  guard xpc_get_type(value) == XPC_TYPE_DICTIONARY else {
    throw EncoderTestError.wrongType
  }
  return value
}

func array(_ parent: xpc_object_t, _ key: String) throws -> xpc_object_t {
  let value = try requiredValue(parent, key)
  guard xpc_get_type(value) == XPC_TYPE_ARRAY else {
    throw EncoderTestError.wrongType
  }
  return value
}

func arrayDictionary(_ array: xpc_object_t, _ index: Int) throws -> xpc_object_t {
  guard index >= 0, index < xpc_array_get_count(array) else {
    throw EncoderTestError.missingValue
  }
  let value = xpc_array_get_value(array, index)
  guard xpc_get_type(value) == XPC_TYPE_DICTIONARY else {
    throw EncoderTestError.wrongType
  }
  return value
}

func value(_ dictionary: xpc_object_t, _ key: String) throws -> xpc_object_t {
  try requiredValue(dictionary, key)
}

func string(_ dictionary: xpc_object_t, _ key: String) throws -> String {
  let value = try requiredValue(dictionary, key)
  guard xpc_get_type(value) == XPC_TYPE_STRING,
    let pointer = xpc_string_get_string_ptr(value)
  else { throw EncoderTestError.wrongType }
  return String(cString: pointer)
}

private func requiredValue(
  _ dictionary: xpc_object_t,
  _ key: String
) throws -> xpc_object_t {
  guard let value = xpc_dictionary_get_value(dictionary, key) else {
    throw EncoderTestError.missingValue
  }
  return value
}
