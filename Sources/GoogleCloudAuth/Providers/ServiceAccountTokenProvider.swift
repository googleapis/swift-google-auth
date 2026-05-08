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

struct ServiceAccountTokenProvider: TokenProvider, Sendable {
  let key: ServiceAccountData
  let scopes: [String]?
  let audience: String?

  init(key: ServiceAccountData, scopes: [String]? = nil, audience: String? = nil) {
    self.key = key
    self.scopes = scopes
    self.audience = audience
  }

  func fetchToken() async throws -> Token {
    // Dummy skeleton fetch returning empty/dummy token
    return Token(
      accessToken: "skeleton-mock-token", expirationDate: Date(timeIntervalSinceNow: 3600))
  }
}

struct ServiceAccountTokenGenerator: Sendable {
  let key: ServiceAccountData
  let scopes: String?
  let audience: String?

  func generate(iat: Int64, exp: Int64) throws -> String {
    return "skeleton-mock-jwt"
  }
}
