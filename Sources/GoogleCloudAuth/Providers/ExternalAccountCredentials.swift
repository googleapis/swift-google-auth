// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import Foundation
#if canImport(FoundationNetworking)
  import FoundationNetworking
#endif

/// Credentials backing Workforce Identity Federation (OIDC / Apple WIF) external accounts.
struct ExternalAccountCredentials: CredentialsSource, Sendable {
  let subjectTokenProvider: any SubjectTokenProvider
  let audience: String
  let subjectTokenType: String
  let tokenURL: URL
  let clientID: String?
  let clientSecret: String?
  let targetPrincipal: String?
  let workforcePoolUserProject: String?
  let scopes: [String]
  let universeDomain: String?

  init(
    subjectTokenProvider: any SubjectTokenProvider,
    audience: String,
    subjectTokenType: String,
    tokenURL: URL,
    clientID: String? = nil,
    clientSecret: String? = nil,
    targetPrincipal: String? = nil,
    workforcePoolUserProject: String? = nil,
    scopes: [String] = [],
    universeDomain: String? = nil
  ) throws {
    // Validate required configuration fields are not empty
    guard !audience.isEmpty else {
      throw CredentialsError.parseError("audience parameter must not be empty")
    }
    guard !subjectTokenType.isEmpty else {
      throw CredentialsError.parseError("subjectTokenType parameter must not be empty")
    }

    // Billing constraints validation: workforce pool user project should only be set for global workforce pools.
    if let workforcePoolUserProject = workforcePoolUserProject, !workforcePoolUserProject.isEmpty {
      guard isValidWorkforcePoolAudience(audience) else {
        throw CredentialsError.parseError(
          "workforcePoolUserProject should not be set for non-workforce pool credentials")
      }
    }

    self.subjectTokenProvider = subjectTokenProvider
    self.audience = audience
    self.subjectTokenType = subjectTokenType
    self.tokenURL = tokenURL
    self.clientID = clientID
    self.clientSecret = clientSecret
    self.targetPrincipal = targetPrincipal
    self.workforcePoolUserProject = workforcePoolUserProject
    self.scopes = scopes
    self.universeDomain = universeDomain
  }

  func headers() async throws -> AuthHeaders {
    // TODO(#267): Stub implementation will be replaced with STS exchange in follow-up PR.
    return []
  }

  func universeDomain() async -> String? {
    return self.universeDomain
  }
}

/// Helper function to validate if the audience refers to a global workforce pool.
private func isValidWorkforcePoolAudience(_ audience: String) -> Bool {
  return audience.hasPrefix("//iam.googleapis.com/locations/global/workforcePools/")
}
