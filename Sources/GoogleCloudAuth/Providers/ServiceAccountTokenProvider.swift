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
import JWTKit

/// The JWT claims structure for generating a Google Cloud Service Account access token.
struct ServiceAccountClaims: JWTPayload, Equatable, Sendable {
  let iss: IssuerClaim
  let sub: SubjectClaim
  let scope: String?
  let aud: AudienceClaim?
  let iat: IssuedAtClaim
  let exp: ExpirationClaim

  func verify(using algorithm: some JWTAlgorithm) async throws {
    // These claims are generated locally for remote Google servers.
    // Local verification is not required.
  }
}

struct ServiceAccountTokenProvider: TokenProvider, Sendable {
  let key: ServiceAccountData
  let scopes: [String]?
  let audience: String?

  private let clockSkewFudgeSeconds: TimeInterval = -10
  private let tokenLifetimeSeconds: TimeInterval = 3600

  init(key: ServiceAccountData, scopes: [String]? = nil, audience: String? = nil) {
    self.key = key
    self.scopes = scopes
    self.audience = audience
  }

  func fetchToken() async throws -> Token {
    let now = Date()
    let iatDate = now.addingTimeInterval(clockSkewFudgeSeconds)
    let expDate = iatDate.addingTimeInterval(tokenLifetimeSeconds)

    let claims = ServiceAccountClaims(
      iss: IssuerClaim(value: key.clientEmail),
      sub: SubjectClaim(value: key.clientEmail),
      scope: scopes?.joined(separator: " "),
      aud: audience.map { AudienceClaim(value: [$0]) },
      iat: IssuedAtClaim(value: iatDate),
      exp: ExpirationClaim(value: expDate)
    )

    let privateKey: Insecure.RSA.PrivateKey
    do {
      privateKey = try Insecure.RSA.PrivateKey(pem: key.privateKey)
    } catch {
      throw CredentialsError.parseError(
        "Failed to parse Service Account RSA Private Key: \(error.localizedDescription)")
    }

    let keys = JWTKeyCollection()
    let kid = JWKIdentifier(string: key.privateKeyID)
    await keys.add(rsa: privateKey, digestAlgorithm: .sha256, kid: kid)

    let signedJWT: String
    do {
      signedJWT = try await keys.sign(claims, kid: kid)
    } catch {
      throw CredentialsError.parseError("RSA JWT signing failed: \(error.localizedDescription)")
    }

    return Token(accessToken: signedJWT, expirationDate: expDate)
  }
}
