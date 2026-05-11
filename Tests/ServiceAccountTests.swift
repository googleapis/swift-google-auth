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

import Testing
import Foundation
@testable import GoogleCloudAuth

@Suite("Service Account Key & Credentials Tests")
struct ServiceAccountTests {
  // A properly formatted mock Service Account JSON key with dummy/mock fields.
  private let mockKeyJSON = """
    {
      "type": "service_account",
      "project_id": "test-project-id",
      "private_key_id": "test-private-key-id",
      "private_key": "-----BEGIN PRIVATE KEY-----\\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQD3l/OR3Ip8jP2v\\n-----END PRIVATE KEY-----\\n",
      "client_email": "test-client-email@gserviceaccount.com",
      "universe_domain": "test-universe-domain"
    }
    """.data(using: .utf8)!

  @Test("Service Account Key debug representation censors the private key")
  func testServiceAccountKeyDebugRepresentation() throws {
    let key = try JSONDecoder().decode(ServiceAccountData.self, from: mockKeyJSON)
    let debugDescription = String(reflecting: key)
    #expect(!debugDescription.contains("MIIEvgIBADANBgkq"))
    #expect(debugDescription.contains("[censored]"))
  }

  @Test("Service Account Credentials returns standard headers successfully")
  func testHeadersSuccessWithoutQuotaProject() async throws {
    let credentials = try ServiceAccountCredentials(keyJSON: mockKeyJSON)
    let headers = try await credentials.headers()

    #expect(headers.count == 1)
    #expect(headers[0].0 == "Authorization")
    #expect(headers[0].1.hasPrefix("Bearer "))
  }

  @Test("Service Account Credentials injects custom billing quota project header")
  func testHeadersSuccessWithQuotaProject() async throws {
    let credentials = try ServiceAccountCredentials(
      keyJSON: mockKeyJSON, quotaProjectID: "quota-proj-123")
    let headers = try await credentials.headers()

    #expect(headers.count == 2)
    #expect(headers.contains { $0.0 == "Authorization" && $0.1.hasPrefix("Bearer ") })
    #expect(headers.contains { $0.0 == "x-goog-user-project" && $0.1 == "quota-proj-123" })
  }
}
