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

import RustAuthCoreBridge

public struct Credentials {
  private let inner: RustAuthCoreBridge.Credentials

  public init() throws {
    self.inner = try RustAuthCoreBridge.Credentials()
  }

  public static func anonymous() -> Credentials {
    return Credentials(inner: RustAuthCoreBridge.Credentials.anonymous())
  }

  private init(inner: RustAuthCoreBridge.Credentials) {
    self.inner = inner
  }

  public func headers() async throws -> [(String, String)] {
    let headers = try await self.inner.headers()
    return headers.map { ($0.key, $0.value) }
  }
}
