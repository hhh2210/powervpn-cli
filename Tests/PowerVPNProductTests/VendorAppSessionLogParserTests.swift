import Testing

@testable import PowerVPNProduct

@Suite struct VendorAppSessionLogParserTests {
  @Test func canonicalTwoSiblingSnapshotSelectsOnlyLogin21AndErases() throws {
    let material = try vendorAppMaterial()

    #expect(material.validation.complete)
    #expect(material.candidate.tunnels?.count == 1)
    material.erase()
    #expect(material.isErased)
    #expect(!material.validation.complete)
  }

  @Test func duplicateCommentsEscapesAndTrailingCommaFailClosed() {
    let malformed = [
      "{ rpc = start_connection; rpc = stop_connection; }",
      "{ rpc = /* comment */ start_connection; }",
      "{ rpc = //comment\n start_connection; }",
      "{ rpc = \\\\start_connection; }",
      "{ rpc = \"start\\nconnection\"; }",
      "{ tunnels = (one,); }",
      "{ \"rpc\" = start_connection; rpc = stop_connection; }",
    ]
    for value in malformed {
      #expect(throws: VendorAppSessionSnapshotError.self) {
        _ = try vendorAppParseComplete(value)
      }
    }
  }

  @Test func integerTypeCanonicalityAndOverflowFailWithoutTrap() {
    let malformed = [
      "status = \"1\";",
      "status = +1;",
      "status = 01;",
      "status = -0;",
      "status = 2147483648;",
      "status = " + String(repeating: "9", count: 100) + ";",
    ]
    for replacement in malformed {
      let root = vendorAppReplacingLogin21Status(with: replacement)
      #expect(throws: VendorAppSessionSnapshotError.self) {
        _ = try vendorAppMaterial(root)
      }
    }
  }

  @Test func selectedResourceMustBeActiveAndUnique() {
    let inactive = vendorAppReplacingLogin21Status(with: "status = 0;")
    let duplicate = vendorAppSyntheticRoot.replacingOccurrences(
      of: "tunnel-name = login52;",
      with: "tunnel-name = login21;"
    )
    for root in [inactive, duplicate] {
      #expect(throws: VendorAppSessionSnapshotError.self) {
        _ = try vendorAppMaterial(root)
      }
    }
  }

  @Test func commonExtrasAndDiscardedSiblingRequireExactKeysAndTypes() {
    let malformed = [
      vendorAppReplacingFirst("    authport = 0;\n", with: ""),
      vendorAppReplacingFirst("dns = \"10.0.0.1\";", with: "dns = ();"),
      vendorAppReplacingFirst("name = synthetic-common;", with: "name = \"synthetic-common\";"),
      vendorAppReplacingFirst("natt_port = 4500;", with: "natt_port = \"4500\";"),
      vendorAppReplacingFirst("authority = 1;", with: "authority = \"1\";"),
      vendorAppReplacingFirst("cmd = \"synthetic-command\";", with: "cmd = synthetic-command;"),
      vendorAppReplacingFirst("enc = aes256;", with: "enc = \"aes256\";"),
      vendorAppReplacingFirst("excludes = ();", with: "excludes = none;"),
      vendorAppReplacingFirst("mapid = \"synthetic-52\";", with: "mapid = synthetic-52;"),
      vendorAppReplacingFirst("notice = \"\";", with: "notice = none;"),
      vendorAppReplacingFirst("family = 4; mask", with: "family = \"4\"; mask"),
      vendorAppReplacingFirst(
        "mask = \"255.255.255.255\"; net = \"11.11.30.52\";",
        with: "mask = 255.255.255.255; net = \"11.11.30.52\";"
      ),
      vendorAppReplacingFirst("net = \"11.11.30.52\";", with: "net = 11.11.30.52;"),
      vendorAppReplacingFirst("prfix = 32;", with: "prfix = \"32\";"),
      vendorAppReplacingFirst("      mapid = \"synthetic-52\";\n", with: ""),
    ]
    for root in malformed {
      #expect(throws: VendorAppSessionSnapshotError.self) {
        _ = try vendorAppMaterial(root)
      }
    }
  }

  @Test func exactGenerationRequiresLogin21AndLogin52Only() {
    for replacement in ["login20", "login53"] {
      let malformed = vendorAppSyntheticRoot.replacingOccurrences(
        of: "tunnel-name = login52;",
        with: "tunnel-name = \(replacement);"
      )
      #expect(throws: VendorAppSessionSnapshotError.self) {
        _ = try vendorAppMaterial(malformed)
      }
    }
  }
}
