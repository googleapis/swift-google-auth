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

@Suite(.serialized) struct CredentialsTest {
  @Test func resolveProviderForAnonymous() async throws {
    let credentials = try Credentials(configuration: .anonymous)

    // Verify the backing provider is the new experimental Swift wrapper shell
    #expect(
      String(describing: type(of: credentials.credentialsSource)).contains("AnonymousCredentials")
    )

    let headers = try await credentials.headers()
    #expect(headers.isEmpty)

    let ud = await credentials.universeDomain()
    #expect(ud == nil)
  }

  @Test func resolveProviderForADC() async throws {
    let credentials = try Credentials(configuration: .adc(environment: [:]))

    #expect(
      String(describing: type(of: credentials.credentialsSource)).contains("MDSCredentials")
    )
  }

  @Test func resolveProviderForUserCredentials() async throws {
    let mockJSON = """
      {
        "client_id": "test-client-id",
        "client_secret": "test-client-secret",
        "refresh_token": "test-refresh-token",
        "type": "authorized_user"
      }
      """
    let dataData = mockJSON.data(using: .utf8)!

    let credentials = try Credentials(configuration: .user(keyJSON: dataData))

    #expect(
      String(describing: type(of: credentials.credentialsSource)).contains("UserCredentials")
    )

    let ud = await credentials.universeDomain()
    #expect(ud == nil)
  }

  @Test func resolveProviderForProgrammaticExternalAccount() async throws {
    struct MockSubjectTokenProvider: SubjectTokenProvider {
      func subjectToken() async throws -> String { "token" }
    }

    let config = ExternalAccountConfig(
      subjectTokenProvider: MockSubjectTokenProvider(),
      audience: "aud",
      subjectTokenType: "urn:ietf:params:oauth:token-type:id_token",
      tokenURL: URL(string: "https://sts.googleapis.com/v1/token")!,
      universeDomain: "my-universe.com"
    )

    let credentials = try Credentials(
      configuration: .programmaticExternalAccount(config)
    )

    #expect(credentials.credentialsSource is ExternalAccountCredentials)

    let ud = await credentials.universeDomain()
    #expect(ud == "my-universe.com")
  }
}
