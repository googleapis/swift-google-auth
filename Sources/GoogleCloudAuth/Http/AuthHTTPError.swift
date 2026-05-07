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

/// Represents any error occurring during an authentication HTTP request.
enum AuthHTTPError: Error, Sendable {
  /// The server returned a non-2xx status code.
  case unsuccessfulResponse(response: HTTPURLResponse, data: Data)
  /// A transport-level error occurred (e.g., timeout, connection lost).
  case transportError(URLError)
  /// A decoding error occurred while parsing the response.
  case decodingError(error: any Error & Sendable, data: Data)
  /// An unexpected or unknown error occurred.
  case unknown(any Error & Sendable)
  /// Failed to decode the response body as a UTF-8 string.
  case invalidUTF8Response
}

extension AuthHTTPError {
  /// The underlying URLError if this is a transport-level error.
  var urlError: URLError? {
    switch self {
    case .transportError(let error):
      return error
    default:
      return nil
    }
  }

  /// The HTTP status code if this is an unsuccessful response.
  var statusCode: Int? {
    switch self {
    case .unsuccessfulResponse(let response, _):
      return response.statusCode
    default:
      return nil
    }
  }

  /// The raw response body as a UTF-8 string if this is an unsuccessful response or a decoding error.
  var body: String? {
    switch self {
    case .unsuccessfulResponse(_, let data):
      return String(data: data, encoding: .utf8)
    case .decodingError(_, let data):
      return String(data: data, encoding: .utf8)
    default:
      return nil
    }
  }

  /// The raw response body data if this is an unsuccessful response or a decoding error.
  var bodyData: Data? {
    switch self {
    case .unsuccessfulResponse(_, let data):
      return data
    case .decodingError(_, let data):
      return data
    default:
      return nil
    }
  }

  /// The HTTP response headers as a string map if this is an unsuccessful response.
  var headers: [String: String]? {
    switch self {
    case .unsuccessfulResponse(let response, _):
      var result: [String: String] = [:]
      for (key, value) in response.allHeaderFields {
        if let keyString = key as? String, let valueString = value as? String {
          result[keyString] = valueString
        }
      }
      return result
    default:
      return nil
    }
  }
}
