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
  private let session: URLSession

  /// Initializes the client with a customized session.
  ///
  /// - Parameter session: The URLSession injected for network dispatching. Defaults to an ephemeral configuration.
  init(session: URLSession? = nil) {
    if let session = session {
      self.session = session
    } else {
      // Ephemeral prevents OS from caching sensitive tokens on disk
      let config = URLSessionConfiguration.ephemeral
      self.session = URLSession(configuration: config)
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
    var request = URLRequest(url: url)
    request.httpMethod = "GET"
    // Bypass any caching to guarantee fresh tokens
    request.cachePolicy = .reloadIgnoringLocalCacheData

    for (key, value) in headers {
      request.setValue(value, forHTTPHeaderField: key)
    }

    let (data, response) = try await self.performRequest(request)
    try self.ensureSuccess(response, data: data)

    return try self.makeDecoder().decode(T.self, from: data)
  }

  /// Asynchronously dispatches a GET request and returns the raw response body as a plain-text string.
  /// Statically required to support local GCE Metadata Server OIDC token and email fetches.
  func getString(
    url: URL,
    headers: [String: String] = [:]
  ) async throws -> String {
    var request = URLRequest(url: url)
    request.httpMethod = "GET"
    request.cachePolicy = .reloadIgnoringLocalCacheData

    for (key, value) in headers {
      request.setValue(value, forHTTPHeaderField: key)
    }

    let (data, response) = try await self.performRequest(request)
    try self.ensureSuccess(response, data: data)

    guard let plainText = String(data: data, encoding: .utf8) else {
      throw URLError(
        .cannotDecodeContentData,
        userInfo: [NSLocalizedDescriptionKey: "Failed to decode UTF-8 string response"]
      )
    }
    return plainText
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

    return try self.makeDecoder().decode(Response.self, from: data)
  }

  // MARK: - Private Helpers

  private func performRequest(_ request: URLRequest) async throws -> (Data, URLResponse) {
    // Support async/await directly on URLSession (handles modern platforms and Linux compatibility)
    #if os(Linux)
      return try await withCheckedThrowingContinuation { continuation in
        let task = self.session.dataTask(with: request) { data, response, error in
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
      return try await self.session.data(for: request)
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
      var userInfo: [String: Any] = [
        NSLocalizedDescriptionKey: "HTTP request failed with status code \(statusCode)"
      ]
      if let bodyString = String(data: data, encoding: .utf8) {
        userInfo["ErrorBody"] = bodyString
      }
      // Include headers in userInfo
      userInfo["ResponseHeaders"] = httpResponse.allHeaderFields

      throw URLError(
        URLError.Code(rawValue: statusCode) ?? .badServerResponse,
        userInfo: userInfo
      )
    }
  }
}
