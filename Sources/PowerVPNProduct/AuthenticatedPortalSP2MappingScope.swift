import PowerVPNPortal

func withAuthenticatedPortalSP2MappingScope<Result>(
  _ snapshot: AuthenticatedPortalSnapshot,
  _ body: (
    PortalSP2ContextTextMaterial,
    Int32,
    [AuthenticatedPortalResourceElement]
  ) throws -> Result
) throws -> Result {
  try snapshot.withPortalContext { context in
    let gateway = try PortalSP2ContextTextMaterial(context)
    return try context.withMajorVersionBytes { majorBytes in
      let majorVersion = try PortalSP2Value.strictInt32(
        majorBytes,
        path: "common.majorVersion"
      )
      return try snapshot.withResourceTree { resourceList in
        let resources = try resourceList.childElements.filter {
          $0.name == AuthenticatedPortalResourceCategory.networkConnect.rawValue
        }
        return try body(gateway, majorVersion, resources)
      }
    }
  }
}
