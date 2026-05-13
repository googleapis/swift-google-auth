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
import RustAuthCoreBridge
import Testing

@testable import GoogleCloudAuth

@Suite(.serialized) struct CredentialsTest {
  @Test func experimentalAuthBackendDefaultsToRust() {
    // Clean any existing env var for test isolation
    setenv("GOOGLE_CLOUD_SWIFT_EXPERIMENTAL_AUTH", "", 1)
    unsetenv("GOOGLE_CLOUD_SWIFT_EXPERIMENTAL_AUTH")

    // Verify that the default backend evaluates to "rust"
    let envVal =
      ProcessInfo.processInfo.environment["GOOGLE_CLOUD_SWIFT_EXPERIMENTAL_AUTH"] ?? "rust"
    #expect(envVal == "rust")
  }

  @Test func resolveRustProviderForAnonymous() async throws {
    // Force backend to Rust
    Credentials.experimentalAuthBackend = "rust"

    let credentials = try Credentials(configuration: .anonymous)

    // Verify the backing provider is the Rust FFI wrapper
    #expect(
      String(describing: type(of: credentials.credentialsSource)).contains("RustCredentialsSource"))

    let headers = try await credentials.headers()
    #expect(headers.isEmpty)
  }

  @Test func resolveSwiftProviderForAnonymous() async throws {
    // Force backend to Swift
    Credentials.experimentalAuthBackend = "swift"

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

  @Test func resolveSwiftProviderForADC() async throws {
    Credentials.experimentalAuthBackend = "swift"

    let credentials = try Credentials(configuration: .adc(environment: [:]))

    #expect(
      String(describing: type(of: credentials.credentialsSource)).contains("MDSCredentials")
    )
  }

  @Test func resolveRustProviderForUserCredentialsThrows() async throws {
    // Force backend to Rust
    Credentials.experimentalAuthBackend = "rust"

    let mockJSON = """
      {
        "client_id": "test-client-id",
        "client_secret": "test-client-secret",
        "refresh_token": "test-refresh-token",
        "type": "authorized_user"
      }
      """
    let dataData = mockJSON.data(using: .utf8)!

    #expect(throws: RustAuthCoreBridge.AuthError.self) {
      _ = try Credentials(configuration: .user(keyJSON: dataData))
    }
  }

  @Test func resolveSwiftProviderForUserCredentials() async throws {
    // Force backend to Swift
    Credentials.experimentalAuthBackend = "swift"

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
}
