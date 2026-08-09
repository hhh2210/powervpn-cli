import Foundation

enum PortalWireContract {
  static let passwordPath = "/vpn/user/auth/password"
  static let resourcePath = "/vpn/user/portal/intergration.xml"
  static let sessionCheckPath = "/vpn/user/check/session"
  static let logoutPath = "/vpn/user/logout"

  static let passwordMethod = "POST"
  static let resourceMethod = "GET"
  static let sessionCheckMethod = "GET"
  static let logoutMethod = "POST"

  static let passwordContentType = "text/xml"
  static let accept = "*/*"

  static func vendorUserAgent(operatingSystemVersion: String) -> String {
    "VSG-libCurl/0.9.9 PowerVPN/3.2.1 (Mac OS X \(operatingSystemVersion))"
  }
}
