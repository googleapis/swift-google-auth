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

#if canImport(FoundationNetworking)
  import FoundationNetworking
#endif

/// An internal provider wrapping the stable Rust FFI credentials core.
struct RustCredentialsSource: CredentialsSource {
  private let inner: RustAuthCoreBridge.Credentials

  init(configuration: CredentialsConfiguration) throws {
    switch configuration {
    case .anonymous:
      self.inner = RustAuthCoreBridge.Credentials.anonymous()
    case .adc:
      self.inner = try RustAuthCoreBridge.Credentials()
    case .serviceAccount:
      throw RustAuthCoreBridge.AuthError.Initialize(
        "Service Account configurations are not supported on the FFI backend.")
    }
  }

  func headers() async throws -> AuthHeaders {
    let headers = try await self.inner.headers()
    return headers.map { ($0.key, $0.value) }
  }

  func universeDomain() async -> String? {
    // Rust client does not expose universe domain; default to nil
    return nil
  }
}
