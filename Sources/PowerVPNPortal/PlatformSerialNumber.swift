import Foundation
import IOKit

enum PlatformSerialNumberError: Error, Equatable, Sendable {
  case unavailable
  case invalid
}

protocol PlatformSerialNumberReading: Sendable {
  func read() throws -> SecureBytes
}

struct InstalledPlatformSerialNumberReader: PlatformSerialNumberReading {
  func read() throws -> SecureBytes {
    guard let matching = IOServiceMatching("IOPlatformExpertDevice") else {
      throw PlatformSerialNumberError.unavailable
    }
    let service = IOServiceGetMatchingService(kIOMainPortDefault, matching)
    guard service != IO_OBJECT_NULL else {
      throw PlatformSerialNumberError.unavailable
    }
    defer { IOObjectRelease(service) }

    guard
      let value = IORegistryEntryCreateCFProperty(
        service,
        "IOPlatformSerialNumber" as CFString,
        kCFAllocatorDefault,
        0
      )?.takeRetainedValue(),
      CFGetTypeID(value) == CFStringGetTypeID()
    else {
      throw PlatformSerialNumberError.unavailable
    }
    let serial = value as! CFString
    let length = CFStringGetLength(serial)
    let maximum = CFStringGetMaximumSizeForEncoding(length, CFStringBuiltInEncodings.UTF8.rawValue)
    guard length > 0, maximum > 0, maximum <= 4_096 else {
      throw PlatformSerialNumberError.invalid
    }

    let buffer = UnsafeMutablePointer<CChar>.allocate(capacity: maximum + 1)
    buffer.initialize(repeating: 0, count: maximum + 1)
    defer {
      _ = memset_s(buffer, maximum + 1, 0, maximum + 1)
      buffer.deinitialize(count: maximum + 1)
      buffer.deallocate()
    }
    guard
      CFStringGetCString(
        serial,
        buffer,
        maximum + 1,
        CFStringBuiltInEncodings.UTF8.rawValue
      )
    else {
      throw PlatformSerialNumberError.invalid
    }
    let byteCount = strnlen(buffer, maximum + 1)
    guard byteCount > 0, byteCount <= maximum else {
      throw PlatformSerialNumberError.invalid
    }
    return try SecureBytes(
      copying: UnsafeRawBufferPointer(start: buffer, count: byteCount)
    )
  }
}
