# Design Specification - Swift Service Account Authentication

This document defines the design and implementation specifications for the native Swift **Service Account Authentication** feature in the `GoogleCloudAuth` package (`packages/auth`). This feature enables applications to authenticate using a Google Service Account JSON key file natively in Swift, eliminating the existing Rust FFI bridge while retaining 100% feature and test parity with the Rust SDK.

---

## 1. Objective & Scope

### Objective
To implement a secure, unified, and thread-safe native Swift Service Account Authentication engine inside `google-cloud-swift` (`packages/auth`), supporting access token generation (self-signed JWTs) and 1-to-1 test parity.

### In-Scope
1.  **Access Token Credentials**: Generating OAuth2 access tokens (self-signed JWS/JWT assertions) natively in Swift using a unified, cross-platform cryptographic library.
2.  **Universal Platform Support**: Functional parity on macOS and Linux out-of-the-box, with a single pure-Swift codebase. (Note: iOS is not a requirement for this phase).
3.  **Thread Safety**: Secure state management and caching via structured concurrency and the `TokenCache` actor.
4.  **Test Parity**: Complete implementation of all validated Rust access-token-specific unit and integration tests in native Swift.

### Out-of-Scope
The following features are explicitly out-of-scope for this phase and are deferred to future work:
1.  **OIDC ID Tokens**: Obtaining OpenID Connect (OIDC) ID tokens for service-to-service authentication (e.g., Cloud Run, IAP) via exchanging signed assertions with the token server.
2.  **Blob Signing / Signer**: Cryptographic RSA-SHA256 signing of arbitrary data payloads locally (e.g., GCS Signed URLs).
3.  **Impersonated Credentials**: Exchanging source credentials for target service account credentials via remote IAM APIs.
4.  **Workload Identity Federation**: Exchanging AWS or OIDC identity tokens for Google access tokens.
5.  **API Keys**: Handling of static raw Google API keys.

---

## 2. Background

Google Cloud client libraries require a unified, thread-safe, and performant authentication mechanism to inject credentials into outgoing HTTP requests. Currently, the `google-cloud-swift` SDK bridges to a shared Rust core `rust_auth_core` via FFI. While functional, this bridge introduces binary bloat, dynamic linking complexities, and toolchain friction in developer environments, particularly on Linux.

To address this, we are transitioning `GoogleCloudAuth` to a pure Swift architecture, utilizing modern language features—such as Structured Concurrency (`async/await`) and Actors—to handle caching natively. This design specification details how to implement the **Service Account Authentication** module natively in Swift, replacing the existing FFI targets while retaining full compatibility with [DESIGN.md](DESIGN.md).

To achieve a highly maintainable, cross-platform, and compile-ready architecture without platform-specific FFI dynamic linking, we adopt a unified **pure-Swift cryptographic strategy** using `CryptoSwift` for RSA-SHA256 signing. Since standard Google Service Account keys are issued in PKCS#8 format, the cryptographic utility integrates a pure-Swift, collection-safe ASN.1 OID header parser to extract the raw PKCS#1 DER key bytes required by `CryptoSwift`'s raw representation initializer.

---

## 3. Requirements

We define functional and non-functional requirements using a binary classification (either required or out-of-scope/deferred). Vague modifiers are avoided to ensure all criteria are testable and clear.

### Functional Requirements
*   **Key Parsing & Format Compatibility**: The library MUST parse Google Service Account JSON keys and load PEM-encoded private keys on macOS and Linux. The private key MUST be formatted in a PEM format natively supported by the platform (PKCS#8). PKCS#1 RSA keys MUST be explicitly rejected with a clear, diagnostic error.
*   **Access Token Generation (Self-Signed JWT)**: The library MUST natively generate RS256 self-signed JWS assertions and utilize them directly as Bearer tokens for Google Cloud API calls, without performing unnecessary token-exchange network roundtrips.
*   **Proactive Caching**: The library MUST cache access tokens in memory and proactively refresh them in the background before they expire to prevent API request latency spikes.

### Non-Functional Requirements
*   **JWS Signing Latency**: Local cryptographic signature computation for JWS assertions MUST have reasonable performance suitable for a one-off operation (as tokens are cached and refreshed hourly). Sub-millisecond signing latency is not a requirement.
*   **Thread Safety**: All stateful token operations, caching, and background refreshing MUST be completely thread-safe and free of data races, implemented natively via Swift structured concurrency and Actor isolation.
*   **GAX Backward Compatibility**: The library MUST maintain complete public API compatibility with GAX `HTTPClient` and generated mono-repo libraries, preserving `AuthHeaders` as duplicate-supporting arrays of key-value tuples.
*   **Acyclic Dependency Boundaries**: The authentication library MUST remain completely independent of `GoogleCloudGax`.

---

## 4. Public API Surface

We will expand the public API defined in the parent [DESIGN.md](DESIGN.md) with explicit configuration options and types for Service Accounts.

### A. Access Token Configuration ([Credentials.swift](../Sources/GoogleCloudAuth/Credentials.swift))

We will add the `serviceAccount` case to `CredentialsConfiguration` inside [Credentials.swift](../Sources/GoogleCloudAuth/Credentials.swift). Note that we do not expose a `serviceAccountKeyFile` case, as reading files is a trivial task that application developers can perform on their own prior to loading credentials:

```swift
public enum CredentialsConfiguration: Sendable {
  /// Automatically resolves credentials using Application Default Credentials (ADC).
  case adc(
    quotaProjectID: String? = nil,
    scopes: [String]? = nil,
    universeDomain: String? = nil
  )

  /// Explicitly signs tokens locally using a Service Account JSON key in memory.
  ///
  /// - Parameters:
  ///   - keyJSON: The raw Service Account JSON key file contents (the entire JSON structure 
  ///     downloaded from the Google Cloud Console containing client_email, private_key_id, 
  ///     private_key, project_id, etc., and not just the raw private key bytes).
  ///   - quotaProjectID: A custom project ID used for billing and quota.
  ///   - universeDomain: Google Cloud universe domain override.
  ///   - scopes: Optional scopes requested (exchanged locally via JWT claims).
  ///   - audience: Optional custom target audience override.
  case serviceAccount(
    keyJSON: Data,
    quotaProjectID: String? = nil,
    universeDomain: String? = nil,
    scopes: [String]? = nil,
    audience: String? = nil
  )
  
  /// Stub credential providing no headers.
  case anonymous
}
```

*Note: To ensure compiler safety for the existing FFI backend during the transition/experimental phase, the `RustCredentialsSource.swift` target MUST be modified to explicitly reject the new configuration by throwing `.notSupported`:*

```swift
case .serviceAccount:
  throw CredentialsError.notSupported("Service Account configurations are not supported on the existing Rust FFI backend.")
```

To support this compilation path, we MUST also modify [MDSCredentials.swift](../Sources/GoogleCloudAuth/Providers/MDSCredentials.swift) to add the new `notSupported` error case to the `CredentialsError` enum:

```swift
public enum CredentialsError: Error, Sendable {
  case gceEnvironmentNotDetected
  case localCredentialsUnsupported
  case generic(message: String, source: (any Error & Sendable)?)
  /// Added to support compilation during the pure-Swift transition phase
  case notSupported(String)
  // ...
}
```

---

## 5. Detailed Architecture & Implementation

### A. Service Account Credentials ([ServiceAccountCredentials.swift](../Sources/GoogleCloudAuth/Providers/ServiceAccountCredentials.swift))

This conforms to `CredentialsSource` inside [ServiceAccountCredentials.swift](../Sources/GoogleCloudAuth/Providers/ServiceAccountCredentials.swift). It manages token fetching and caching for Service Account access tokens. It integrates with the generic `TokenCache` actor from the codebase, explicitly specifying `ContinuousClock` as its generic type argument.

```swift
struct ServiceAccountCredentials: CredentialsSource, Sendable {
  private let tokenProvider: TokenCache<ContinuousClock>
  private let quotaProjectID: String?
  private let universeDomain: String?

  init(
    keyJSON: Data,
    quotaProjectID: String? = nil,
    universeDomain: String? = nil,
    scopes: [String]? = nil,
    audience: String? = nil
  ) throws {
    let key = try JSONDecoder().decode(ServiceAccountKey.self, from: keyJSON)
    let provider = ServiceAccountTokenProvider(key: key, scopes: scopes, audience: audience)
    
    self.tokenProvider = TokenCache(provider: provider)
    self.quotaProjectID = quotaProjectID
    self.universeDomain = universeDomain ?? key.universeDomain
  }

  func headers() async throws -> AuthHeaders {
    let token = try await tokenProvider.token()
    var headers: AuthHeaders = [("Authorization", "Bearer \(token.accessToken)")]
    if let quotaProjectID = quotaProjectID {
      headers.append(("x-goog-user-project", quotaProjectID))
    }
    return headers
  }

  func universeDomain() async -> String? {
    return self.universeDomain
  }
}
```

### B. Service Account Key ([ServiceAccountKey.swift](../Sources/GoogleCloudAuth/Providers/ServiceAccountKey.swift))

Represents the parsed JSON key file, encapsulates key loading, and safely censors the private key for logging. We omit the manual `init(from:)` implementation to allow the compiler to automatically synthesize both the decodable JSON initializer and the default memberwise initializer required by the tests.

```swift
struct ServiceAccountKey: Decodable, Sendable {
  let clientEmail: String
  let privateKeyID: String
  let privateKey: String
  let projectID: String
  let universeDomain: String?

  enum CodingKeys: String, CodingKey {
    case clientEmail = "client_email"
    case privateKeyID = "private_key_id"
    case privateKey = "private_key"
    case projectID = "project_id"
    case universeDomain = "universe_domain"
  }
}

extension ServiceAccountKey: CustomDebugStringConvertible {
  var debugDescription: String {
    "ServiceAccountKey(clientEmail: \"\(clientEmail)\", privateKeyID: \"\(privateKeyID)\", privateKey: \"[censored]\", projectID: \"\(projectID)\", universeDomain: \(universeDomain ?? "nil"))"
  }
}
```

### C. Self-Signed JWT Generation ([ServiceAccountTokenProvider.swift](../Sources/GoogleCloudAuth/Providers/ServiceAccountTokenProvider.swift))

Natively generates JWS structures inside [JWS.swift](../Sources/GoogleCloudAuth/Crypto/JWS.swift) and performs local RSA signing using a unified, pure-Swift cryptographic utility.

#### 1. JWS Types ([JWS.swift](../Sources/GoogleCloudAuth/Crypto/JWS.swift))

```swift
struct JWSHeader: Codable, Sendable {
  let alg = "RS256"
  let typ = "JWT"
  let kid: String
}

struct JWSClaims: Codable, Sendable {
  let iss: String
  let sub: String
  let scope: String?
  let aud: String?
  let iat: Int64
  let exp: Int64
}
```

#### 2. JWS Claims Serialization & Mapping Rules

To ensure GCP compatibility, JWS claims must be serialized following these exact mapping rules:
*   **`iss` and `sub`**: MUST be set to the service account's `clientEmail` value.
*   **`iat` (Issued At)**: MUST be set to the current UNIX epoch timestamp minus `10 seconds` to accommodate slight clock skew between server and client.
*   **`exp` (Expiration)**: MUST be set strictly relative to `iat` as `iat + 3600` (exactly 60 minutes). **Setting `exp` relative to `now` (e.g. `now + 3600 + 10`) will create a token lifetime of 3610 seconds, which Google Cloud's IAM endpoint will reject with a token expiration lifecycle error.**
*   **Mutually Exclusive `scope` and `aud`**:
    *   *Scopes Flow*: If the configuration defines scopes, the JWS MUST include the `scope` claim containing space-separated OAuth2 scope strings (e.g., `"https://www.googleapis.com/auth/cloud-platform"`), and the `aud` claim MUST be serialized as `null` (or omitted entirely).
    *   *Audience Flow*: If the configuration defines an audience, the JWS MUST include the `aud` claim containing the target service name (e.g., `"https://pubsub.googleapis.com/"`), and the `scope` claim MUST be serialized as `null` (or omitted).

#### 3. Token Generation Flow
The `ServiceAccountTokenProvider` conforms to the generic `TokenProvider` protocol from the codebase, implementing `fetchToken()` instead of `token()`, and returning `Token` structs using `accessToken` and `expirationDate`.

```swift
struct ServiceAccountTokenProvider: TokenProvider, Sendable {
  let key: ServiceAccountKey
  let scopes: [String]?
  let audience: String?
  
  func fetchToken() async throws -> Token {
    let generator = ServiceAccountTokenGenerator(
      key: key,
      scopes: scopes?.joined(separator: " "),
      audience: audience
    )
    
    // Synchronously align calculated iat/exp claims and cache expiration.
    let now = Int64(Date().timeIntervalSince1970)
    let iat = now - 10 // 10s clock skew fudge
    let exp = iat + 3600
    
    let signedJWT = try generator.generate(iat: iat, exp: exp)
    let expiry = Date(timeIntervalSince1970: TimeInterval(exp))
    
    return Token(accessToken: signedJWT, expirationDate: expiry)
  }
}

struct ServiceAccountTokenGenerator: Sendable {
  let key: ServiceAccountKey
  let scopes: String?
  let audience: String?

  func generate(iat: Int64, exp: Int64) throws -> String {
    let claims = JWSClaims(
      iss: key.clientEmail,
      sub: key.clientEmail,
      scope: scopes,
      aud: audience, // If scopes are used, this will be nil (serialized as omitted or null)
      iat: iat,
      exp: exp
    )
    
    let header = JWSHeader(kid: key.privateKeyID)
    
    let encoder = JSONEncoder()
    encoder.outputFormatting = .sortedKeys
    
    let headerData = try encoder.encode(header)
    let claimsData = try encoder.encode(claims)
    
    let headerB64 = headerData.base64URLEncodedString()
    let claimsB64 = claimsData.base64URLEncodedString()
    let signingInput = "\(headerB64).\(claimsB64)"
    
    let messageData = Data(signingInput.utf8)
    let signature = try CryptoSwiftSignatureUtility.sign(
      message: messageData,
      privateKeyPEM: key.privateKey
    )
    
    let signatureB64 = signature.base64URLEncodedString()
    return "\(signingInput).\(signatureB64)"
  }
}
```

*Note: Base64URL encoding utilities will be implemented as extensions on `Data`.*

---

### D. Supporting Utility Types & Extensions

We will implement the supporting `CryptoError` enum and necessary extensions to `AuthHTTPClient`.

#### 1. CryptoError ([CryptoError.swift](../Sources/GoogleCloudAuth/Crypto/CryptoError.swift))

```swift
enum CryptoError: Error, Sendable {
  case invalidPrivateKey(String)
  case algorithmNotSupported
  case signingFailed(String)
  case invalidPEMFormat
}
```

#### 2. AuthHTTPClient Extensions ([AuthHTTPClient.swift](../Sources/GoogleCloudAuth/Http/AuthHTTPClient.swift))

We implement the generic `send<T>()` method directly inside `AuthHTTPClient.swift` (instead of a separate file/extension). This preserves strict modular encapsulation, keeping the core HTTP helpers (`performRequest`, `ensureSuccess`, and `makeDecoder`) fully `private` to the struct.

```swift
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

extension AuthHTTPClient {
  /// Thread-safe global shared instance.
  static let shared = AuthHTTPClient()

  /// Asynchronously sends an arbitrary URLRequest and decodes a JSON response.
  func send<T: Decodable>(_ request: URLRequest) async throws -> T {
    let (data, response) = try await self.performRequest(request)
    try self.ensureSuccess(response, data: data)
    return try self.makeDecoder().decode(T.self, from: data)
  }
}
```

---

## 6. Cryptographic Implementation Strategy ([CryptoSwiftSignatureUtility.swift](../Sources/GoogleCloudAuth/Crypto/CryptoSwiftSignatureUtility.swift))

Implementing RSA-SHA256 signing natively in Swift across platforms is accomplished using a unified, cross-platform cryptographic helper `CryptoSwiftSignatureUtility` backing the `CryptoSwift` package. 

Google Service Account private keys are always issued in **PKCS#8** PEM containers. However, `CryptoSwift`'s raw representation initializer strictly only accepts the raw **PKCS#1** DER private key bytes. To resolve this cross-platform, `CryptoSwiftSignatureUtility` integrates a robust, collection-safe ASN.1 parsing helper `stripPKCS8Header(from:)` (safely indexing sliced `Data` buffers using `.endIndex`) to extract the inner PKCS#1 key structure dynamically, before loading it into `RSA(rawRepresentation:)`.

This ensures a clean, unified codebase, completely eliminating platform preprocessor guards and complex FFI packaging.

```swift
import CryptoSwift
import Foundation

struct CryptoSwiftSignatureUtility: Sendable {
  static func sign(message: Data, privateKeyPEM: String) throws -> Data {
    // 1. Parse PEM to extract raw DER bytes
    let derData = try parsePEMToDER(privateKeyPEM)
    
    // 2. Strip PKCS#8 OID headers to extract the inner PKCS#1 RSA key for CryptoSwift compatibility
    guard let pkcs1Data = stripPKCS8Header(from: derData) else {
      throw CryptoError.invalidPrivateKey("Failed to extract PKCS#1 RSA key from PKCS#8 container.")
    }
    
    // 3. Initialize CryptoSwift RSA key using PKCS#1 DER bytes and perform signing
    do {
      let rsa = try RSA(rawRepresentation: pkcs1Data)
      let signature = try rsa.sign(message.bytes, variant: .sha256)
      return Data(signature)
    } catch {
      throw CryptoError.signingFailed("CryptoSwift RSA signing failed: \(error.localizedDescription)")
    }
  }
  
  private static func parsePEMToDER(_ pem: String) throws -> Data {
    // Explicitly intercept PKCS#1 formatted RSA keys and throw a highly descriptive diagnostic error
    if pem.contains("-----BEGIN RSA PRIVATE KEY-----") {
      throw CryptoError.invalidPrivateKey("PKCS#1 keys are not supported. Please convert your service account private key to PKCS#8 format.")
    }

    let cleanPEM = pem
      .replacingOccurrences(of: "-----BEGIN PRIVATE KEY-----", with: "")
      .replacingOccurrences(of: "-----END PRIVATE KEY-----", with: "")
      .replacingOccurrences(of: "\n", with: "")
      .replacingOccurrences(of: "\r", with: "")
      .trimmingCharacters(in: .whitespacesAndNewlines)
    
    guard let derData = Data(base64Encoded: cleanPEM) else {
      throw CryptoError.invalidPEMFormat
    }
    return derData
  }

  /// Parses the ASN.1 structure with collection-safe endIndex bounds validation to strip the PKCS#8 header.
  private static func stripPKCS8Header(from data: Data) -> Data? {
    let rsaOID = Data([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01])
    guard let oidRange = data.range(of: rsaOID) else { return nil }

    var index = oidRange.upperBound
    if index + 1 < data.endIndex && data[index] == 0x05 && data[index + 1] == 0x00 {
      index += 2
    }

    guard index < data.endIndex, data[index] == 0x04 else { return nil }
    index += 1 // Consume octet tag

    guard index < data.endIndex else { return nil }

    if data[index] > 0x7f {
      let lengthBytesCount = Int(data[index] & 0x7f)
      guard index + 1 + lengthBytesCount <= data.endIndex else { return nil }
      index += 1 + lengthBytesCount
    } else {
      index += 1
    }

    guard index <= data.endIndex else { return nil }
    return data.subdata(in: index..<data.endIndex)
  }
}
```

---

## 7. Modular Integration & Package Layout ([Package.swift](../Package.swift))

We will clean up the existing FFI bridge targets and declare `CryptoSwift` as a production dependency in `packages/auth/Package.swift`.

```swift
dependencies: [
  .package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", from: "1.10.0")
],
targets: [
  .target(
    name: "GoogleCloudAuth",
    dependencies: [
      .product(name: "CryptoSwift", package: "CryptoSwift")
    ]
  ),
  .testTarget(
    name: "GoogleCloudAuthTests",
    dependencies: ["GoogleCloudAuth"],
    path: "Tests"
  ),
]
```

---

## 8. Alternatives Considered

We evaluated three cryptographic alternatives for native RSA-SHA256 signing, framing our trade-offs decisively:

*   *We considered Alternative 1 (CryptoSwift) because it provides a pure-Swift cryptographic engine, and Alternative 2 (swift-crypto) for its standard API. We went with Alternative 1 (CryptoSwift) because it provides a unified, cross-platform pure-Swift signature computation that compiles cleanly on macOS and Linux, utilizing our safe ASN.1 OID header stripper to feed PKCS#1 DER bytes natively. This completely removes FFI complexity, platform preprocessor guards, and C target dynamic linking setup. We deferred Alternative 3 (BoringSSL/Security) due to the massive code complexity (CoreFoundation CFError pointers, dynamic linking errors on Linux).*

### Alternative 1: Use `CryptoSwift` (Chosen Strategy)
`CryptoSwift` is a pure Swift cryptography library.
*   *Benefits*: Clean, unified, cross-platform codebase. Simplifies the package layout and eliminates platform preprocessor guards and dynamic linking.
*   *Trade-off*: Introducing a third-party pure-Swift cryptographic library in production requires a mandatory security review to ensure cryptographic boundary safety and memory-clear security policies.

### Alternative 2: Integrate Apple's `swift-crypto`
We considered integrating Apple's open-source cross-platform `swift-crypto` package.
*   *Why Deferred*: `swift-crypto` does not support RSA-SHA256 signing out of the box. Furthermore, bringing `swift-crypto` in as a production dependency pulls in a heavy transitive package graph (including `swift-crypto` and `swift-asn1`), bloating our dependency graph and introducing target compile conflict risks for downstream applications.

### Alternative 3: Platform-Specific APIs (Apple `Security` & Linux C-Bridge `CAuthBoringSSL`)
Implement native `Security.framework` on Apple, and a thin C-bridge target wrapping host OpenSSL/BoringSSL C functions on Linux.
*   *Why Deferred*: While highly secure, it introduces severe code complexity, requiring custom ASN.1 stripping algorithms to parse PKCS#8 headers on Apple platforms, unsafe memory-pointer bindings, dynamic linking complexities on Linux hosts, and conditional compile environments.

---

## 9. Test Parity Strategy

To preserve safety, we map all verified Rust service-account-specific tests directly to native Swift tests using `import Testing`.

### A. Test Structure Example
All tests MUST be structured using modern Swift Testing:

```swift
import Testing
@testable import GoogleCloudAuth

@Suite("Service Account Key Tests")
struct ServiceAccountTests {
  @Test("Service Account Key debug representation censors private key")
  func serviceAccountKeyDebugRepresentation() {
    let key = ServiceAccountKey(clientEmail: "a@b.com", privateKeyID: "123", privateKey: "secret", projectID: "p123", universeDomain: nil)
    let debug = String(reflecting: key)
    #expect(!debug.contains("secret"))
    #expect(debug.contains("[censored]"))
  }
}
```

### B. Unit Test Parity ([ServiceAccountTests.swift](../Tests/ServiceAccountTests.swift))

1.  `debug_token_provider` -> `testServiceAccountKeyDebugRepresentation()`
    *   Verifies `CustomDebugStringConvertible` for `ServiceAccountKey` censors the private key.
2.  `headers_success_without_quota_project` -> `testHeadersSuccessWithoutQuotaProject()`
    *   Verifies `Authorization` header exists and `x-goog-user-project` is absent.
3.  `headers_success_with_quota_project` -> `testHeadersSuccessWithQuotaProject()`
    *   Verifies `x-goog-user-project` is present.
4.  `headers_failure` -> `testHeadersFailurePropagates()`
    *   Asserts token provider errors are successfully bubbled up from `headers()`.
5.  `get_service_account_headers_pkcs1_private_key_failure` -> `testPKCS1KeyBuildFails()`
    *   Expects `.invalidPrivateKey` or parsing error when attempting to parse a PKCS#1 key (only PKCS#8 is supported).
6.  `get_service_account_token_pkcs8_key_success` -> `testPKCS8KeyGenerationSuccess()`
    *   Decodes generated JWT, verifying JWS headers (`alg: RS256`, `typ: JWT`, `kid`), issuer, scope, and default lifetime.
7.  `header_caching` -> `testTokenAndHeaderCaching()`
    *   Validates that consecutive calls to `headers()` return the cached token instead of regenerating JWT and signing.
8.  `universe_domain` -> `testUniverseDomainParsingAndOverrides()`
    *   Verifies default `googleapis.com`, key-specific domains, and explicit overrides propagate correctly.
9.  `get_service_account_headers_invalid_key_failure` -> `testInvalidKeySigningFailure()`
    *   Asserts invalid PEM strings fail gracefully.
10. `get_service_account_invalid_json_failure` -> `testInvalidJSONParsingFailure()`
    *   Asserts invalid JSON strings fail to build.
11. `get_service_account_headers_with_audience` -> `testJWSAssertionWithAudience()`
    *   Verifies JWS claims set `aud` and omit `scope` when built with audience.
12. `get_service_account_headers_with_custom_scopes` -> `testJWSAssertionWithCustomScopes()`
    *   Verifies JWS claims set space-separated `scope` and omit `aud` when built with scopes.
13. `get_service_account_access_token` -> `testBuildAccessTokenCredentials()`
    *   Verifies constructing and querying `AccessTokenCredentials`.

### C. Integration Test Parity ([IntegrationTests.swift](../../../Tests/IntegrationTests/IntegrationTests.swift))

1.  `create_access_token_credentials_adc_service_account_credentials` -> `testAdcResolvesServiceAccountCredentials()`
    *   Loads service account key into env, triggers ADC, and asserts `ServiceAccountCredentials` is resolved.
2.  `create_access_token_credentials_json_service_account_credentials` -> `testAdcResolvesServiceAccountWithQuota()`
    *   Asserts ADC resolves service account credentials with quota project.

---

## 10. Risks and Mitigation Strategies

We identify critical implementation risks and establish clear, strategic mitigations.

### A. Pure-Swift Cryptographic Security Boundary Audits
*   **Risk**: Deploying a third-party pure-Swift cryptographic library (`CryptoSwift`) in production code involves a security risk regarding cryptographic implementation correctness, side-channel attacks, and overall package safety.
*   **Mitigation**: 
    *   A **mandatory security review** MUST be scheduled and completed before shipping the library to production.
    *   Lock and pin the `CryptoSwift` dependency package version, monitor standard security advisories, and verify that compiler optimization flags do not introduce side-channel leaks.

### B. Raw Key Memory Security
*   **Risk**: Parsing private keys into in-memory `String` or `Data` buffers creates a risk of key exposure via memory heap inspections.
*   **Mitigation**: Maintain extremely tight scope lifecycles for deserialized keys. Where supported, clear raw byte arrays (`[UInt8]`) or zero out private key structures immediately after cryptographic key load and signature operations.

---

# Corpus of information

*   [AIP-4110: Application Default Credentials](https://google.aip.dev/auth/4110)
*   [AIP-4111: Self-Signed JWTs](https://google.aip.dev/auth/4111)
*   [RFC 7519: JSON Web Token (JWT)](https://datatracker.ietf.org/doc/html/rfc7519)
*   [RFC 7523: JWT Profile for OAuth 2.0 Client Authentication](https://datatracker.ietf.org/doc/html/rfc7523)
*   [Apple Developer: SecKey Cryptographic Signing Docs](https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/signing_and_verifying)
