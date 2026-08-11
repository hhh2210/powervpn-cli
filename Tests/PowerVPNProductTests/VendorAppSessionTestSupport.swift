import PowerVPNCore

@testable import PowerVPNProduct

let vendorAppSyntheticRoot = """
  {
    type = rpc;
    rpc = "start_connection";
    common = {
      authport = 0;
      dns = "10.0.0.1";
      dnsv6 = "";
      esp = "aes256-sha256";
      gateway = "166.111.143.19";
      ike = "aes256-sha256";
      ike_life_time = 3600;
      ike_port = 500;
      ipsec_life_time = 3600;
      majorVersion = 3;
      name = synthetic-common;
      natt_port = 4500;
      psk = synthetic-psk;
      sessionid = "synthetic-session";
      status = 1;
      subnet = "255.255.255.0";
      tunnelnameV4 = login21;
      vip = "10.0.0.8";
      vipv6 = "";
    };
    tunnels = (
      {
        authority = 1;
        cmd = "synthetic-command";
        display = 1;
        enc = aes256;
        excludes = ();
        status = 1;
        tunnel-name = login52;
        family = 4;
        icon = "";
        rflag = 0;
        name = "";
        routes = ({ family = 4; mask = "255.255.255.255"; net = "11.11.30.52"; prfix = 32; });
        mapid = "synthetic-52";
        negotiate-mode = 1;
        notice = "";
      },
      {
        authority = 1;
        cmd = "synthetic-command";
        display = 1;
        enc = aes256;
        excludes = ();
        status = 1;
        tunnel-name = login21;
        family = 4;
        icon = "";
        rflag = 0;
        name = "";
        routes = ({ family = 4; mask = "255.255.255.255"; net = "11.11.30.21"; prfix = 32; });
        mapid = "synthetic-21";
        negotiate-mode = 1;
        notice = "";
      }
    );
  }
  """

func vendorAppSyntheticRecord(root: String = vendorAppSyntheticRoot) -> String {
  "2026-08-11 12:34:56.789 com.leadsec.charon-xpc[123:456] "
    + "charon xpc handle request:"
    + root
    + " \n"
}

func vendorAppParseComplete(_ text: String) throws -> VendorAppSessionLogNode {
  let bytes = Array(text.utf8)
  return try bytes.withUnsafeBytes { raw in
    var parser = VendorAppSessionLogParser(bytes: raw)
    return try parser.parseComplete()
  }
}

func vendorAppMaterial(
  _ rootText: String = vendorAppSyntheticRoot,
  sourceSeal: VendorAppSessionSourceSeal? = nil,
  sourceCurrent: (@Sendable () -> Bool)? = nil
) throws
  -> VendorAppSessionSnapshotMaterial
{
  let bytes = Array(rootText.utf8)
  return try bytes.withUnsafeBytes { raw in
    var parser = VendorAppSessionLogParser(bytes: raw)
    let root = try parser.parseComplete()
    return try VendorAppSessionSnapshotMaterial(
      root: root,
      bytes: raw,
      sourceSeal: sourceSeal,
      sourceCurrent: sourceCurrent
    )
  }
}

func vendorAppLocatedRecord(_ text: String) throws -> VendorAppSessionLocatedRecord {
  let bytes = Array(text.utf8)
  return try bytes.withUnsafeBytes(VendorAppSessionRecordFraming.singleStartRecord)
}

func vendorAppReplacingLogin21Status(with assignment: String) -> String {
  var root = vendorAppSyntheticRoot
  let nameRange = root.range(of: "tunnel-name = login21;")!
  let prefix = root[..<nameRange.lowerBound]
  let statusRange = prefix.range(of: "status = 1;", options: .backwards)!
  root.replaceSubrange(statusRange, with: assignment)
  return root
}

func vendorAppReplacingFirst(_ value: String, with replacement: String) -> String {
  var root = vendorAppSyntheticRoot
  guard let range = root.range(of: value) else {
    preconditionFailure("synthetic vendor fixture replacement not found")
  }
  root.replaceSubrange(range, with: replacement)
  return root
}
