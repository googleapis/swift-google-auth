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

/// Represents any error occurring during credentials resolution or initialization.
public enum CredentialsError: Error, Sendable, Hashable {
  /// Indicates that the requested operation or credential type is not supported by the current backend.
  case notSupported(String)

  /// Indicates a failure while parsing or decoding configuration data (e.g., malformed JSON key).
  case parseError(String)

  /// Application Default Credentials (ADC) could not resolve a valid configuration.
  ///
  /// ## Troubleshooting
  ///
  /// Could not fetch an auth token to authenticate with Google Cloud. The most common reason
  /// for this problem is that you are not running in a Google Cloud environment and you have
  /// not configured local credentials for development and testing.
  ///
  /// To setup local credentials, run `gcloud auth application-default login`. More information
  /// on how to authenticate client libraries can be found at
  /// https://cloud.google.com/docs/authentication/client-libraries
  case missingEnvironmentConfiguration(String)
}

extension CredentialsError: LocalizedError {
  public var errorDescription: String? {
    switch self {
    case .notSupported(let detail):
      return "Operation not supported: \(detail)"
    case .parseError(let detail):
      return "Configuration parse error: \(detail)"
    case .missingEnvironmentConfiguration(let context):
      return """
        Could not fetch an auth token to authenticate with Google Cloud. The most common reason for this problem is that you are not running in a Google Cloud environment and you have not configured local credentials for development and testing.
        To setup local credentials, run `gcloud auth application-default login`. More information on how to authenticate client libraries can be found at https://cloud.google.com/docs/authentication/client-libraries

        Context: \(context)
        """
    }
  }
}

/// Defines the configurations for authenticating Google Cloud API requests.
public enum CredentialsConfiguration: Sendable {
  /// Automatically resolves credentials using Application Default Credentials (ADC).
  case adc(
    quotaProjectID: String? = nil,
    universeDomain: String? = nil,
    scopes: [String] = [],
    environment: [String: String]? = nil
  )

  /// Returns a stub credential that provides no headers (unauthenticated).
  case anonymous

  /// Explicitly signs JWS assertions locally using a Service Account JSON key in memory.
  ///
  /// - Parameters:
  ///   - keyJSON: The raw Service Account JSON key file contents.
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
  public init(configuration: CredentialsConfiguration = .adc()) throws {
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
    case let .adc(quotaProjectID, universeDomain, scopes, environment):
      return try ADC.resolve(
        quotaProjectID: quotaProjectID,
        universeDomain: universeDomain,
        scopes: scopes,
        environment: environment ?? ProcessInfo.processInfo.environment
      )
    case .anonymous:
      return AnonymousCredentials()
    case let .serviceAccount(keyJSON, quotaProjectID, universeDomain, scopes, audience):
      return try ServiceAccountCredentials(
        keyJSON: keyJSON,
        quotaProjectID: quotaProjectID,
        universeDomain: universeDomain,
        scopes: scopes,
        audience: audience
      )
    }
  }
}
