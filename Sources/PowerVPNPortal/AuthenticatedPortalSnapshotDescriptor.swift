func describeAuthenticatedPortalSnapshot(
  _ document: PortalXMLDocument
) throws -> AuthenticatedPortalSnapshotDescriptor {
  let integration = try LeadSecPortalProfile.integrationInfo(document)
  let resourceLists = integration?.childElements.filter { $0.name == "RESOURCE_LIST" } ?? []
  guard resourceLists.count <= 1 else {
    throw AuthenticatedPortalSnapshotError.duplicateResourceList
  }
  let children = resourceLists.first?.childElements ?? []
  let observations = AuthenticatedPortalResourceCategory.allCases.map { category in
    AuthenticatedPortalCategoryObservation(
      category: category,
      nodeCount: children.count { $0.name == category.rawValue }
    )
  }
  return AuthenticatedPortalSnapshotDescriptor(
    authenticatedPortalSessionPresent: true,
    integrationInfoPresent: integration != nil,
    resourceListPresent: resourceLists.count == 1,
    categoryObservations: observations
  )
}
