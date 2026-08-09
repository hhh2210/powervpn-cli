import Testing

@testable import PowerVPNPortal

@Suite struct SecurePortalRequestBodyTests {
  @Test func encode1MatchesIndependentVendorOrderedVector() throws {
    let credentials = PortalCredentials(
      username: try SecureBytes(copying: Array("alice".utf8)),
      password: try SecureBytes(copying: Array("s3cret".utf8))
    )
    let serial = try SecureBytes(copying: Array("SERIAL-01".utf8))
    defer {
      credentials.erase()
      serial.erase()
    }

    let body = try PortalPasswordBodyBuilder.encode1(
      credentials: credentials,
      platformSerial: serial
    )
    defer { body.erase() }

    let expected = Array(
      "encode='1'&hardware_hash=SERIAL-01&password=czNjcmV0&terminal_type=mac&type=app&username=YWxpY2U="
        .utf8
    )
    #expect(try body.withUnsafeBytes { $0.elementsEqual(expected) })
  }

  @Test(arguments: [
    ("f", "Zg=="),
    ("fo", "Zm8="),
    ("foo", "Zm9v"),
    ("foob", "Zm9vYg=="),
    ("fooba", "Zm9vYmE="),
    ("foobar", "Zm9vYmFy"),
  ])
  func base64TailShapesMatchReference(_ input: String, _ expected: String) throws {
    let credentials = PortalCredentials(
      username: try SecureBytes(copying: Array(input.utf8)),
      password: try SecureBytes(copying: [0x78])
    )
    let serial = try SecureBytes(copying: [0x53])
    defer {
      credentials.erase()
      serial.erase()
    }
    let body = try PortalPasswordBodyBuilder.encode1(
      credentials: credentials,
      platformSerial: serial
    )
    defer { body.erase() }

    let suffix = Array("&username=\(expected)".utf8)
    #expect(
      try body.withUnsafeBytes { bytes in
        bytes.suffix(suffix.count).elementsEqual(suffix)
      }
    )
  }

  @Test func opaqueUTF8BytesAreEncodedWithoutNormalizationOrPercentEscaping() throws {
    let credentials = PortalCredentials(
      username: try SecureBytes(copying: [0x00, 0xff, 0x26, 0x3d]),
      password: try SecureBytes(copying: [0x2b, 0x2f])
    )
    let serial = try SecureBytes(copying: Array("A&B=C".utf8))
    defer {
      credentials.erase()
      serial.erase()
    }
    let body = try PortalPasswordBodyBuilder.encode1(
      credentials: credentials,
      platformSerial: serial
    )
    defer { body.erase() }

    #expect(
      try body.withUnsafeBytes { bytes in
        bytes.elementsEqual(
          Array(
            "encode='1'&hardware_hash=A&B=C&password=Ky8=&terminal_type=mac&type=app&username=AP8mPQ=="
              .utf8
          )
        )
      }
    )
  }

  @Test func emptySerialFailsClosed() throws {
    let credentials = PortalCredentials(
      username: try SecureBytes(copying: [0x61]),
      password: try SecureBytes(copying: [0x62])
    )
    let serial = try SecureBytes(copying: [])
    defer { credentials.erase() }

    #expect(throws: PortalPasswordBodyError.emptySerial) {
      _ = try PortalPasswordBodyBuilder.encode1(
        credentials: credentials,
        platformSerial: serial
      )
    }
  }

  @Test func requestBodyErasesOwnedBytes() throws {
    let credentials = PortalCredentials(
      username: try SecureBytes(copying: [0x61]),
      password: try SecureBytes(copying: [0x62])
    )
    let serial = try SecureBytes(copying: [0x53])
    let body = try PortalPasswordBodyBuilder.encode1(
      credentials: credentials,
      platformSerial: serial
    )
    body.erase()
    #expect(body.count == 0)
    #expect(throws: SecureBytesError.erased) {
      _ = try body.withUnsafeBytes(\.count)
    }
  }
}
