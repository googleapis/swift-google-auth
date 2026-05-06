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

/// Represents the HTTP request header fields required to authenticate an API query.
/// Formatted as an array of key-value tuples to natively support duplicate header names.
public typealias AuthHeaders = [(String, String)]

/// Defines the configurations for authenticating Google Cloud API requests.
public enum CredentialsConfiguration: Sendable {
  /// Automatically resolves credentials using Application Default Credentials (ADC).
  case adc

  /// Returns a stub credential that provides no headers (unauthenticated).
  case anonymous
}

/// A type that can provide authentication headers for Google Cloud API requests.
protocol CredentialsSource: Sendable {
  /// Asynchronously retrieves the request headers required to authenticate a request.
  ///
  /// - Returns: An array of key-value tuples representing HTTP headers.
  func headers() async throws -> AuthHeaders

  /// Retrieves the universe domain associated with the credentials.
  ///
  /// - Returns: The universe domain string, or nil if not configured or available.
  func universeDomain() async -> String?
}

/// The public entry point to authenticate Google Cloud API requests.
public struct Credentials: Sendable {
  /// Configuration switch for the experimental authentication backend.
  /// Can be set to "rust" or "swift". Defaults to "rust" (FFI-based).
  /// Can be initialized via `GOOGLE_CLOUD_SWIFT_EXPERIMENTAL_AUTH` environment variable.
  public nonisolated(unsafe) static var experimentalAuthBackend: String = {
    ProcessInfo.processInfo.environment["GOOGLE_CLOUD_SWIFT_EXPERIMENTAL_AUTH"] ?? "rust"
  }()

  let credentialsSource: any CredentialsSource

  /// Initializes credentials using a specific configuration (defaults to automatic ADC resolution).
  public init(configuration: CredentialsConfiguration = .adc) throws {
    if Self.experimentalAuthBackend == "swift" {
      self.credentialsSource = try Self.resolveSwiftCredentialsSource(configuration: configuration)
    } else {
      self.credentialsSource = try Self.resolveRustCredentialsSource(configuration: configuration)
    }
  }

  /// Asynchronously retrieves the request headers required to authenticate a request.
  public func headers() async throws -> AuthHeaders {
    return try await self.credentialsSource.headers()
  }

  /// Retrieves the universe domain associated with the credentials.
  public func universeDomain() async -> String? {
    return await self.credentialsSource.universeDomain()
  }

  // MARK: - Backend Resolvers

  private static func resolveRustCredentialsSource(configuration: CredentialsConfiguration) throws
    -> any CredentialsSource
  {
    return try RustCredentialsSource(configuration: configuration)
  }

  private static func resolveSwiftCredentialsSource(configuration: CredentialsConfiguration) throws
    -> any CredentialsSource
  {
    switch configuration {
    case .adc:
      return try ADC.resolve()
    case .anonymous:
      return AnonymousCredentials()
    }
  }
}
