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
import Testing

@testable import GoogleCloudAuth

private struct MockSubjectTokenProvider: SubjectTokenProvider {
  let token: String

  func subjectToken() async throws -> String {
    return token
  }
}

@Suite("External Account Credentials Configuration Tests")
struct ExternalAccountTests {
  @Test("Configures programmatic credentials with custom providers successfully")
  func createProgrammaticCredentials() throws {
    let provider = MockSubjectTokenProvider(token: "mock-provider-token")
    let targetURL = URL(string: "https://sts.googleapis.com/v1/token")!

    let creds = try ExternalAccountCredentials(
      subjectTokenProvider: provider,
      audience:
        "//iam.googleapis.com/projects/123/locations/global/workloadPools/pool/providers/prov",
      subjectTokenType: "urn:ietf:params:oauth:token-type:id_token",
      tokenURL: targetURL,
      clientID: "client-id",
      clientSecret: "client-secret",
      targetPrincipal: "target-sa",
      workforcePoolUserProject: nil,
      scopes: ["scope1", "scope2"],
      universeDomain: "custom-universe.com"
    )

    #expect(
      creds.audience
        == "//iam.googleapis.com/projects/123/locations/global/workloadPools/pool/providers/prov")
    #expect(creds.subjectTokenType == "urn:ietf:params:oauth:token-type:id_token")
    #expect(creds.tokenURL == targetURL)
    #expect(creds.clientID == "client-id")
    #expect(creds.clientSecret == "client-secret")
    #expect(creds.targetPrincipal == "target-sa")
    #expect(creds.workforcePoolUserProject == nil)
    #expect(creds.scopes == ["scope1", "scope2"])
    #expect(creds.universeDomain == "custom-universe.com")
  }

  @Test("Configures custom billing quota project programmatically")
  func createProgrammaticCredentialsWithQuotaProjectID() throws {
    let provider = MockSubjectTokenProvider(token: "mock-provider-token")
    let targetURL = URL(string: "https://sts.googleapis.com/v1/token")!

    let creds = try ExternalAccountCredentials(
      subjectTokenProvider: provider,
      audience: "//iam.googleapis.com/locations/global/workforcePools/wpool/providers/wprov",
      subjectTokenType: "urn:ietf:params:oauth:token-type:id_token",
      tokenURL: targetURL,
      workforcePoolUserProject: "quota-project"
    )

    #expect(creds.workforcePoolUserProject == "quota-project")
  }

  @Test("Configures programmatic credentials universe domains correctly")
  func programmaticCredentialsWithUniverseDomain() throws {
    let provider = MockSubjectTokenProvider(token: "mock-provider-token")
    let targetURL = URL(string: "https://sts.googleapis.com/v1/token")!

    let creds = try ExternalAccountCredentials(
      subjectTokenProvider: provider,
      audience: "aud",
      subjectTokenType: "urn:ietf:params:oauth:token-type:id_token",
      tokenURL: targetURL,
      universeDomain: "my-universe.com"
    )

    #expect(creds.universeDomain == "my-universe.com")
  }

  @Test("Validates missing programmatic fields throw error during initialization")
  func createProgrammaticCredentialsFailsOnMissingRequiredField() throws {
    let provider = MockSubjectTokenProvider(token: "mock-provider-token")
    let targetURL = URL(string: "https://sts.googleapis.com/v1/token")!

    // Empty audience should throw parseError
    #expect(throws: CredentialsError.self) {
      _ = try ExternalAccountCredentials(
        subjectTokenProvider: provider,
        audience: "",
        subjectTokenType: "urn:ietf:params:oauth:token-type:id_token",
        tokenURL: targetURL
      )
    }

    // Empty subjectTokenType should throw parseError
    #expect(throws: CredentialsError.self) {
      _ = try ExternalAccountCredentials(
        subjectTokenProvider: provider,
        audience: "aud",
        subjectTokenType: "",
        tokenURL: targetURL
      )
    }
  }

  @Test("Enforces audience validation throwing error if workforce project is set on workload pools")
  func programmaticCredentialsWorkforcePoolUserProjectFailsWithoutWorkforcePoolAudience() throws {
    let provider = MockSubjectTokenProvider(token: "mock-provider-token")
    let targetURL = URL(string: "https://sts.googleapis.com/v1/token")!

    // Non-workforce pool audience: starting with projects/ instead of locations/global/workforcePools/
    let workloadAudience =
      "//iam.googleapis.com/projects/123/locations/global/workloadPools/wpool/providers/wprov"

    #expect(throws: CredentialsError.self) {
      _ = try ExternalAccountCredentials(
        subjectTokenProvider: provider,
        audience: workloadAudience,
        subjectTokenType: "urn:ietf:params:oauth:token-type:id_token",
        tokenURL: targetURL,
        workforcePoolUserProject: "billing-project"
      )
    }
  }

  @Test(
    "Validates authorization and billing quota headers match outgoing requirements",
    .disabled("PR3"))
  func programmaticCredentialsReturnsCorrectHeaders() async throws {}

  @Test("Successfully signs tokens and performs service account impersonation", .disabled("PR3"))
  func externalAccountWithImpersonationSuccess() async throws {}

  @Test(
    "Successfully returns the direct STS access token when no impersonation is active",
    .disabled("PR3"))
  func externalAccountWithoutImpersonationSuccess() async throws {}

  @Test(
    "Constructs valid AccessTokenCredentials from programmatic configurations", .disabled("PR3"))
  func externalAccountAccessTokenCredentialsSuccess() async throws {}

  @Test("Propagates transient errors when the STS endpoint fails with a 500", .disabled("PR3"))
  func impersonationFlowSTSCallFails() async throws {}

  @Test(
    "Immediately aborts and throws permanent errors on 403 Forbidden IAM exceptions",
    .disabled("PR3"))
  func impersonationFlowIAMCallFails() async throws {}

  @Test("Programmatic credentials retry correctly on transient errors", .disabled("PR3"))
  func programmaticCredentialsRetriesOnTransientFailures() async throws {}

  @Test("Programmatic credentials do not retry on non-transient failures", .disabled("PR3"))
  func programmaticCredentialsDoesNotRetryOnNonTransientFailures() async throws {}

  @Test(
    "Programmatic credentials recover successfully on transient retry conditions", .disabled("PR3"))
  func programmaticCredentialsRetriesForSuccess() async throws {}

  @Test(
    "Bypasses userProject options payload when client authentication is active", .disabled("PR3"))
  func stsHandlerIgnoresWorkforcePoolUserProjectWithClientAuth() async throws {}

  @Test(
    "Injects serialized userProject JSON options during token exchange form posts", .disabled("PR3")
  )
  func stsHandlerReceivesWorkforcePoolUserProject() async throws {}
}
