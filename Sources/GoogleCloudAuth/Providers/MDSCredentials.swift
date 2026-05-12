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

/// Creates credentials backed by the local GCP Compute Engine Metadata Service (MDS).
struct MDSCredentials: CredentialsSource, Sendable {
  let quotaProjectID: String?

  init(quotaProjectID: String? = nil) {
    self.quotaProjectID = quotaProjectID
  }

  // MARK: - CredentialsSource

  /// Asynchronously retrieves mock empty headers for the skeleton phase.
  func headers() async throws -> [(String, String)] {
    return []
  }

  /// Retrieves the universe domain string override.
  func universeDomain() async -> String? {
    return nil
  }
}
