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
import Testing

@testable import GoogleCloudAuth

// MARK: - Mock Concurrency-Safe Token Provider Actor

private actor MockTokenProvider: TokenProvider {
  private var fetchCount = 0
  private var nextToken: Token?
  private var nextError: Error?

  func configure(token: Token?, error: Error? = nil) {
    self.nextToken = token
    self.nextError = error
  }

  var count: Int {
    self.fetchCount
  }

  func fetchToken() async throws -> Token {
    self.fetchCount += 1
    if let error = self.nextError {
      throw error
    }
    guard let token = self.nextToken else {
      throw URLError(.unknown)
    }
    return token
  }
}

private actor DelayedTokenProvider: TokenProvider {
  private let token: Token
  private var fetchCount = 0

  init(token: Token) {
    self.token = token
  }

  var count: Int { self.fetchCount }

  func fetchToken() async throws -> Token {
    self.fetchCount += 1
    try await Task.sleep(for: .seconds(0.1))
    return self.token
  }
}

private actor DelayedFailedTokenProvider: TokenProvider {
  private let error: Error
  private var fetchCount = 0

  init(error: Error) {
    self.error = error
  }

  var count: Int { self.fetchCount }

  func fetchToken() async throws -> Token {
    self.fetchCount += 1
    try await Task.sleep(for: .seconds(0.1))
    throw self.error
  }
}

// MARK: - Suite: TokenCache Test

@Suite struct TokenCacheTest {
  @Test func cacheFetchesTokenWhenEmpty() async throws {
    let provider = MockTokenProvider()
    let expectedToken = Token(
      accessToken: "token-1", expirationDate: Date().addingTimeInterval(1000))
    await provider.configure(token: expectedToken)

    let cache = await TokenCache(provider: provider)
    let token = try await cache.token()

    #expect(token.accessToken == "token-1")
    #expect(await provider.count == 1)
  }

  @Test func cacheReturnsCachedTokenWhenValid() async throws {
    let provider = MockTokenProvider()
    let expectedToken = Token(
      accessToken: "token-1", expirationDate: Date().addingTimeInterval(1000))
    await provider.configure(token: expectedToken)

    let cache = await TokenCache(provider: provider)

    // First call fetches from provider
    let token1 = try await cache.token()
    #expect(token1.accessToken == "token-1")

    // Second call returns cached value instantly
    let token2 = try await cache.token()
    #expect(token2.accessToken == "token-1")
    #expect(await provider.count == 1)  // Count remains 1
  }

  @Test func cacheRefreshesWhenTokenIsStale() async throws {
    let provider = MockTokenProvider()

    // Expiration date is 1.5 seconds from now (less than 2s normalRefreshSlack)
    let staleToken = Token(
      accessToken: "stale-token", expirationDate: Date().addingTimeInterval(1.5))
    await provider.configure(token: staleToken)

    // Use very short slack values for testing!
    let cache = await TokenCache(
      provider: provider,
      normalRefreshSlack: .seconds(2),  // Consider stale if expires in < 2s
      shortRefreshSlack: .seconds(0.1)  // Poll every 0.1s if stale
    )

    // First call fetches the stale token
    let token1 = try await cache.token()
    #expect(token1.accessToken == "stale-token")

    // Re-configure provider with a new fresh token
    let freshToken = Token(
      accessToken: "fresh-token", expirationDate: Date().addingTimeInterval(1000))
    await provider.configure(token: freshToken)

    // Wait a bit to allow the background loop to poll and refresh!
    try await Task.sleep(for: .seconds(0.5))

    // Second call should return the fresh token!
    let token2 = try await cache.token()
    #expect(token2.accessToken == "fresh-token")
    #expect(await provider.count == 2)  // Count is 2!
  }

  @Test func concurrentCallsShareActiveTaskPreventingThunderingHerds() async throws {
    let provider = MockTokenProvider()
    let expectedToken = Token(
      accessToken: "shared-token", expirationDate: Date().addingTimeInterval(1000))
    await provider.configure(token: expectedToken)

    let cache = await TokenCache(provider: provider)

    // Spawn 5 concurrent requests to token() simultaneously
    let results = try await withThrowingTaskGroup(of: Token.self) { group in
      for _ in 1...5 {
        group.addTask {
          try await cache.token()
        }
      }

      var tokens: [Token] = []
      for try await token in group {
        tokens.append(token)
      }
      return tokens
    }

    // Verify all 5 concurrent callers received the same token
    #expect(results.count == 5)
    for token in results {
      #expect(token.accessToken == "shared-token")
    }

    // Verify only ONE fetch operation was executed on the backend!
    #expect(await provider.count == 1)
  }

  @Test func cachePropagatesErrorAndAllowsRetries() async throws {
    let provider = MockTokenProvider()
    let expectedError = URLError(.userAuthenticationRequired)
    await provider.configure(token: nil, error: expectedError)

    // Use short slack to make retry fast
    let cache = await TokenCache(
      provider: provider,
      normalRefreshSlack: .seconds(2),
      shortRefreshSlack: .seconds(0.1)
    )

    // First attempt should propagate the exact error from the provider
    await #expect(throws: URLError.self) {
      try await cache.token()
    }

    #expect(await provider.count == 1)

    // Re-configure provider to succeed with a fresh token
    let freshToken = Token(
      accessToken: "fresh-token", expirationDate: Date().addingTimeInterval(1000))
    await provider.configure(token: freshToken)

    // Wait for the background loop to retry
    try await Task.sleep(for: .seconds(0.2))

    // Second attempt should succeed, proving active task was cleared and retried
    let token = try await cache.token()
    #expect(token.accessToken == "fresh-token")
    #expect(await provider.count == 2)
  }

  @Test func cacheAbortsRefreshLoopOnPermanentError() async throws {
    let provider = MockTokenProvider()
    let expectedError = URLError(.userAuthenticationRequired)
    await provider.configure(token: nil, error: expectedError)

    let cache = await TokenCache(
      provider: provider,
      normalRefreshSlack: .seconds(2),
      shortRefreshSlack: .seconds(0.1),
      isRetryable: { _ in false }  // Treat all errors as permanent
    )

    // First attempt should fail
    await #expect(throws: URLError.self) {
      try await cache.token()
    }

    // Wait long enough for background loop to poll if it didn't abort
    try await Task.sleep(for: .seconds(0.5))

    // If it aborted, count should still be 1
    #expect(await provider.count == 1)
  }

  @Test func expiredTokenFailure() async throws {
    let provider = MockTokenProvider()
    let now = Date()

    let initialToken = Token(
      accessToken: "initial-token", expirationDate: now.addingTimeInterval(1.0))
    await provider.configure(token: initialToken)

    let cache = await TokenCache(
      provider: provider,
      normalRefreshSlack: .seconds(0.5),
      shortRefreshSlack: .seconds(0.1)
    )

    let token1 = try await cache.token()
    #expect(token1.accessToken == "initial-token")

    try await Task.sleep(for: .seconds(1.2))

    await provider.configure(token: nil, error: URLError(.badServerResponse))

    await #expect(throws: URLError.self) {
      try await cache.token()
    }
  }

  @Test func refreshTaskExpiredTokenLoop() async throws {
    let provider = MockTokenProvider()

    let expiredToken = Token(
      accessToken: "expired-token", expirationDate: Date().addingTimeInterval(-10))
    await provider.configure(token: expiredToken)

    let cache = await TokenCache(
      provider: provider,
      normalRefreshSlack: .seconds(2),
      shortRefreshSlack: .seconds(0.1)
    )

    let token1 = try await cache.token()
    #expect(token1.accessToken == "expired-token")

    let freshToken = Token(
      accessToken: "fresh-token", expirationDate: Date().addingTimeInterval(1000))
    await provider.configure(token: freshToken)

    try await Task.sleep(for: .seconds(1.2))

    let token2 = try await cache.token()
    #expect(token2.accessToken == "fresh-token")
  }

  @Test func noInitialTokenThunderingHerdSuccess() async throws {
    let expectedToken = Token(
      accessToken: "shared-token", expirationDate: Date().addingTimeInterval(1000))
    let provider = DelayedTokenProvider(token: expectedToken)

    let cache = await TokenCache(provider: provider)

    let results = try await withThrowingTaskGroup(of: Token.self) { group in
      for _ in 1...5 {
        group.addTask {
          try await cache.token()
        }
      }

      var tokens: [Token] = []
      for try await token in group {
        tokens.append(token)
      }
      return tokens
    }

    #expect(results.count == 5)
    for token in results {
      #expect(token.accessToken == "shared-token")
    }

    #expect(await provider.count == 1)
  }

  @Test func tokenCacheMultipleRequestsExistingValidToken() async throws {
    let provider = MockTokenProvider()
    let expectedToken = Token(
      accessToken: "valid-token", expirationDate: Date().addingTimeInterval(1000))
    await provider.configure(token: expectedToken)

    let cache = await TokenCache(provider: provider)

    // Fetch once to populate cache
    _ = try await cache.token()

    // Spawn N tasks, all asking for a token at once
    let results = try await withThrowingTaskGroup(of: Token.self) { group in
      for _ in 1...5 {
        group.addTask {
          try await cache.token()
        }
      }

      var tokens: [Token] = []
      for try await token in group {
        tokens.append(token)
      }
      return tokens
    }

    #expect(results.count == 5)
    for token in results {
      #expect(token.accessToken == "valid-token")
    }

    // Verify only ONE fetch operation was executed total!
    #expect(await provider.count == 1)
  }

  @Test func noInitialTokenThunderingHerdFailureSharesError() async throws {
    let expectedError = URLError(.userAuthenticationRequired)
    let provider = DelayedFailedTokenProvider(error: expectedError)

    let cache = await TokenCache(provider: provider)

    // Spawn N tasks, all asking for a token at once
    await #expect(throws: URLError.self) {
      try await withThrowingTaskGroup(of: Token.self) { group in
        for _ in 1...5 {
          group.addTask {
            try await cache.token()
          }
        }

        for try await _ in group {
          // Should throw before returning any token
        }
      }
    }

    // Verify only ONE fetch operation was executed!
    #expect(await provider.count == 1)
  }

  @Test func testDebugTokenCache() async {
    let provider = MockTokenProvider()
    let cache = await TokenCache(provider: provider)

    let debugDescription = String(reflecting: cache)
    #expect(debugDescription.contains("TokenCache"))
  }

  @Test func initTriggersFetchImmediately() async throws {
    let provider = MockTokenProvider()
    let expectedToken = Token(
      accessToken: "token-1", expirationDate: Date().addingTimeInterval(1000))
    await provider.configure(token: expectedToken)

    let _ = await TokenCache(provider: provider)

    // Wait for the first attempt to be recorded
    while await provider.count < 1 {
      try await Task.sleep(for: .seconds(0.01))
    }
    #expect(await provider.count == 1)
  }

  @Test func testTokenThrowsPermanentError() async throws {
    let provider = MockTokenProvider()
    let expectedError = URLError(.userAuthenticationRequired)
    await provider.configure(token: nil, error: expectedError)

    let cache = await TokenCache(
      provider: provider,
      normalRefreshSlack: .seconds(2),
      shortRefreshSlack: .seconds(0.1),
      isRetryable: { _ in false }  // Treat all errors as permanent
    )

    // Wait for the background loop to fail and set permanentError
    try await Task.sleep(for: .seconds(0.5))

    // Calling token() should throw the permanent error
    await #expect {
      try await cache.token()
    } throws: { error in
      guard let urlError = error as? URLError else { return false }
      return urlError.code == .userAuthenticationRequired
    }

    // Verify count is 1 (it didn't retry)
    #expect(await provider.count == 1)

    // Call it again, should still throw the SAME error without calling provider
    await #expect {
      try await cache.token()
    } throws: { error in
      guard let urlError = error as? URLError else { return false }
      return urlError.code == .userAuthenticationRequired
    }

    #expect(await provider.count == 1)
  }

  @Test func testRefreshTaskSleepsUntilStale() async throws {
    let provider = MockTokenProvider()
    let now = Date()

    // Token expires in 0.5 seconds
    let token = Token(
      accessToken: "token-1", expirationDate: now.addingTimeInterval(0.5))
    await provider.configure(token: token)

    let cache = await TokenCache(
      provider: provider,
      normalRefreshSlack: .seconds(0.2),  // Stale if expires in < 0.2s
      shortRefreshSlack: .seconds(0.05)
    )

    // Wait for the first fetch to complete (triggered by init)
    while await provider.count < 1 {
      try await Task.sleep(for: .seconds(0.01))
    }

    // Now background loop should calculate sleep: 0.5 - 0.2 = 0.3 seconds

    // Re-configure provider to return a new token on next fetch
    let nextToken = Token(
      accessToken: "token-2", expirationDate: Date().addingTimeInterval(1000))
    await provider.configure(token: nextToken)

    // Wait 0.1 seconds (less than 0.3s sleep). Should NOT have fetched again!
    try await Task.sleep(for: .seconds(0.1))
    #expect(await provider.count == 1)

    // Wait another 0.6 seconds (total 0.7s, well past the 0.5s expiration). Should HAVE fetched again!
    try await Task.sleep(for: .seconds(0.6))
    #expect(await provider.count == 2)

    let fetchedToken = try await cache.token()
    #expect(fetchedToken.accessToken == "token-2")
  }
}
