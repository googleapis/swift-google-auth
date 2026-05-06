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

/// Represents an access token used to authenticate requests.
struct Token: Sendable, Hashable {
  /// The raw token string (e.g. Bearer access token).
  let accessToken: String
  /// The date/time when the token will expire.
  let expirationDate: Date

  /// Initializes a token with an access string and expiration.
  ///
  /// - Parameters:
  ///   - accessToken: The raw token string.
  ///   - expirationDate: The date/time when the token expires.
  init(accessToken: String, expirationDate: Date) {
    self.accessToken = accessToken
    self.expirationDate = expirationDate
  }
}

/// A type that can fetch authentication tokens from a backend source.
protocol TokenProvider: Sendable {
  /// Asynchronously fetches a fresh token from the provider.
  ///
  /// - Returns: A fresh token.
  func fetchToken() async throws -> Token
}

/// A thread-safe generic actor that caches and refreshes tokens on-demand.
actor TokenCache {
  private let provider: any TokenProvider
  private var cachedToken: Token?
  private var activeRefreshTask: Task<Token, Error>?

  /// Expirations buffer: tokens are considered stale if they expire in less than 4 minutes (240 seconds).
  private static let defaultNormalRefreshSlack: Duration = .seconds(240)
  private static let defaultShortRefreshSlack: Duration = .seconds(10)

  private let normalRefreshSlack: Duration
  private let shortRefreshSlack: Duration
  private let isRetryable: @Sendable (Error) -> Bool
  private var backgroundTask: Task<Void, Never>?
  private var permanentError: Error?

  /// Initializes the cache wrapping a concrete token provider source.
  ///
  /// - Parameters:
  ///   - provider: The underlying token provider.
  ///   - normalRefreshSlack: Slack time for normal refresh.
  ///   - shortRefreshSlack: Slack time for short refresh (polling).
  ///   - isRetryable: Closure to determine if an error is transient. Defaults to always retry.
  init(
    provider: any TokenProvider,
    normalRefreshSlack: Duration = defaultNormalRefreshSlack,
    shortRefreshSlack: Duration = defaultShortRefreshSlack,
    isRetryable: @Sendable @escaping (Error) -> Bool = { _ in true }
  ) async {
    self.provider = provider
    self.normalRefreshSlack = normalRefreshSlack
    self.shortRefreshSlack = shortRefreshSlack
    self.isRetryable = isRetryable

    // Trigger first fetch immediately so activeRefreshTask is populated on startup
    _ = self.triggerRefresh()

    self.backgroundTask = Task { [weak self] in
      await self?.runRefreshLoop()
    }
  }

  deinit {
    backgroundTask?.cancel()
  }

  /// Asynchronously retrieves a valid token from the cache, executing a refresh if stale or missing.
  ///
  /// Concurrent requests will share the same active refresh task, preventing thundering herds.
  ///
  /// - Note: If a permanent error occurs during background refresh, the refresh loop terminates
  ///         and all subsequent calls to this method will fail with that same error indefinitely.
  ///
  /// - Returns: A valid, non-stale token.
  func token() async throws -> Token {
    if let error = self.permanentError {
      throw error
    }

    if let cached = self.cachedToken, !self.isExpired(cached) {
      return cached
    }

    // Return active task if exists, or trigger a new refresh
    return try await self.triggerRefresh().value
  }

  // MARK: - Private Helpers

  private func isExpired(_ token: Token) -> Bool {
    return token.expirationDate <= Date()
  }

  private func isStale(_ token: Token) -> Bool {
    let seconds = Double(self.normalRefreshSlack.components.seconds)
    let thresholdDate = Date().addingTimeInterval(seconds)
    return token.expirationDate <= thresholdDate
  }

  private func triggerRefresh() -> Task<Token, Error> {
    if let task = self.activeRefreshTask {
      return task
    }

    let task = Task {
      return try await self.provider.fetchToken()
    }
    self.activeRefreshTask = task

    // Clear task and update cache when done
    Task { [weak self] in
      do {
        let token = try await task.value
        await self?.updateCache(with: token)
      } catch {
        await self?.clearActiveTask()
      }
    }

    return task
  }

  private func updateCache(with token: Token) {
    self.cachedToken = token
    self.activeRefreshTask = nil
  }

  private func clearActiveTask() {
    self.activeRefreshTask = nil
  }

  private func runRefreshLoop() async {
    while !Task.isCancelled {
      // If we already have a valid, non-stale token, sleep until it becomes stale
      if let cached = self.cachedToken, !self.isStale(cached) {
        let timeUntilStale =
          cached.expirationDate.timeIntervalSinceNow
          - Double(self.normalRefreshSlack.components.seconds)
        if timeUntilStale > 0 {
          try? await Task.sleep(for: .seconds(timeUntilStale))
          continue
        }
      }

      let task = self.triggerRefresh()

      do {
        let token = try await task.value

        let timeUntilExpiry = token.expirationDate.timeIntervalSinceNow
        let duration = Duration.seconds(timeUntilExpiry)

        if duration > self.normalRefreshSlack {
          try await Task.sleep(for: duration - self.normalRefreshSlack)
        } else if duration > self.shortRefreshSlack {
          try await Task.sleep(for: self.shortRefreshSlack)
        } else {
          // Expired or very close to it, retry immediately after a short break
          try await Task.sleep(for: .seconds(1))
        }
      } catch {
        if error is CancellationError {
          break
        }
        // On permanent errors, break the loop to prevent endless polling
        if !self.isRetryable(error) {
          self.permanentError = error
          break
        }
        // Handle transient errors by sleeping and retrying
        try? await Task.sleep(for: self.shortRefreshSlack)
      }
    }
  }
}

extension TokenCache: CustomDebugStringConvertible {
  nonisolated var debugDescription: String {
    return "TokenCache"
  }
}
