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

/// A lightweight, portable, and secure HTTP request client dedicated to authentication requests.
struct AuthHTTPClient: Sendable {
  private static let sharedSession = URLSession(configuration: .ephemeral)
  private let sessionProvider: @Sendable () -> URLSession

  /// Initializes the client with a dynamic session provider closure.
  ///
  /// - Parameter sessionProvider: A closure returning a `URLSession` for network dispatching.
  init(sessionProvider: @Sendable @escaping () -> URLSession) {
    self.sessionProvider = sessionProvider
  }

  /// Initializes the client with a customized static session.
  ///
  /// - Parameter session: The static `URLSession` injected for network dispatching. Defaults to constructing an ephemeral configuration on demand.
  init(session: URLSession? = nil) {
    if let session = session {
      self.sessionProvider = { session }
    } else {
      self.sessionProvider = { Self.sharedSession }
    }
  }

  /// Asynchronously dispatches a GET request and decodes the generic JSON response.
  ///
  /// - Parameters:
  ///   - url: The target URL of the request.
  ///   - headers: HTTP request headers.
  /// - Returns: The parsed JSON response structure.
  func get<T: Decodable>(
    url: URL,
    headers: [String: String] = [:]
  ) async throws -> T {
    return try await self.mapError {
      var request = URLRequest(url: url)
      request.httpMethod = "GET"
      request.cachePolicy = .reloadIgnoringLocalCacheData

      for (key, value) in headers {
        request.setValue(value, forHTTPHeaderField: key)
      }

      let (data, response) = try await self.performRequest(request)
      try self.ensureSuccess(response, data: data)

      do {
        return try self.makeDecoder().decode(T.self, from: data)
      } catch let error as DecodingError {
        throw AuthHTTPError.decodingError(error: error, data: data)
      }
    }
  }

  /// Asynchronously dispatches a GET request and returns the raw response body as a plain-text string.
  /// Statically required to support local GCE Metadata Server OIDC token and email fetches.
  func getString(
    url: URL,
    headers: [String: String] = [:]
  ) async throws -> String {
    return try await self.mapError {
      var request = URLRequest(url: url)
      request.httpMethod = "GET"
      request.cachePolicy = .reloadIgnoringLocalCacheData

      for (key, value) in headers {
        request.setValue(value, forHTTPHeaderField: key)
      }

      let (data, response) = try await self.performRequest(request)
      try self.ensureSuccess(response, data: data)

      guard let plainText = String(data: data, encoding: .utf8) else {
        throw AuthHTTPError.decodingError(error: AuthHTTPError.invalidUTF8Response, data: data)
      }
      return plainText
    }
  }

  /// Asynchronously dispatches a POST request sending generic JSON body and decodes the JSON response.
  ///
  /// - Parameters:
  ///   - url: The target URL of the request.
  ///   - body: The encodable JSON body structure.
  ///   - headers: HTTP request headers.
  /// - Returns: The parsed JSON response structure.
  func post<Body: Encodable, Response: Decodable>(
    url: URL,
    body: Body,
    headers: [String: String] = [:]
  ) async throws -> Response {
    return try await self.mapError {
      var request = URLRequest(url: url)
      request.httpMethod = "POST"
      request.cachePolicy = .reloadIgnoringLocalCacheData
      request.setValue("application/json", forHTTPHeaderField: "Content-Type")

      for (key, value) in headers {
        request.setValue(value, forHTTPHeaderField: key)
      }

      request.httpBody = try self.makeEncoder().encode(body)

      let (data, response) = try await self.performRequest(request)
      try self.ensureSuccess(response, data: data)

      do {
        return try self.makeDecoder().decode(Response.self, from: data)
      } catch let error as DecodingError {
        throw AuthHTTPError.decodingError(error: error, data: data)
      }
    }
  }

  /// Asynchronously dispatches a POST request sending raw data and decodes the JSON response.
  ///
  /// - Parameters:
  ///   - url: The target URL of the request.
  ///   - bodyData: The raw data to send as the HTTP body.
  ///   - contentType: The Content-Type header value.
  ///   - headers: HTTP request headers.
  /// - Returns: The parsed JSON response structure.
  func postData<Response: Decodable>(
    url: URL,
    bodyData: Data,
    contentType: String,
    headers: [String: String] = [:]
  ) async throws -> Response {
    return try await self.mapError {
      var request = URLRequest(url: url)
      request.httpMethod = "POST"
      request.cachePolicy = .reloadIgnoringLocalCacheData
      request.setValue(contentType, forHTTPHeaderField: "Content-Type")

      for (key, value) in headers {
        request.setValue(value, forHTTPHeaderField: key)
      }

      request.httpBody = bodyData

      let (data, response) = try await self.performRequest(request)
      try self.ensureSuccess(response, data: data)

      do {
        return try self.makeDecoder().decode(Response.self, from: data)
      } catch let error as DecodingError {
        throw AuthHTTPError.decodingError(error: error, data: data)
      }
    }
  }

  // MARK: - Private Helpers

  /// Centralizes error mapping logic to wrap any transport or unknown failures in AuthHTTPError.
  private func mapError<T>(
    _ operation: () async throws -> T
  ) async throws -> T {
    do {
      return try await operation()
    } catch let error as AuthHTTPError {
      throw error
    } catch let error as URLError {
      throw AuthHTTPError.transportError(error)
    } catch {
      throw AuthHTTPError.unknown(error)
    }
  }

  private func performRequest(_ request: URLRequest) async throws -> (Data, URLResponse) {
    let session = self.sessionProvider()

    // Support async/await directly on URLSession (handles modern platforms and Linux compatibility)
    #if os(Linux)
      return try await withCheckedThrowingContinuation { continuation in
        let task = session.dataTask(with: request) { data, response, error in
          if let error = error {
            continuation.resume(throwing: error)
          } else if let data = data, let response = response {
            continuation.resume(returning: (data, response))
          } else {
            continuation.resume(
              throwing: URLError(
                .unknown, userInfo: [NSLocalizedDescriptionKey: "Empty HTTP response"]))
          }
        }
        task.resume()
      }
    #else
      return try await session.data(for: request)
    #endif
  }

  private func makeDecoder() -> JSONDecoder {
    let decoder = JSONDecoder()
    decoder.keyDecodingStrategy = .convertFromSnakeCase
    return decoder
  }

  private func makeEncoder() -> JSONEncoder {
    let encoder = JSONEncoder()
    encoder.keyEncodingStrategy = .convertToSnakeCase
    return encoder
  }

  private func ensureSuccess(_ response: URLResponse, data: Data) throws {
    guard let httpResponse = response as? HTTPURLResponse else {
      throw URLError(
        .badServerResponse, userInfo: [NSLocalizedDescriptionKey: "Non-HTTP URL response received"])
    }

    let statusCode = httpResponse.statusCode
    guard (200...299).contains(statusCode) else {
      throw AuthHTTPError.unsuccessfulResponse(response: httpResponse, data: data)
    }
  }
}
