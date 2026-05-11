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

import Testing
import Foundation
@testable import GoogleCloudAuth

@Suite("ADC Path Resolution Tests")
struct ADCPathTests {
  @Test("ADC well-known path Windows", .disabled("Unimplemented"))
  func testADCWellKnownPathWindows() {
    let env = ["APPDATA": "C:/Users/foo"]
    let path = resolveWellKnownADCPath(environment: env, isWindows: true)
    #expect(path?.path == "C:/Users/foo/gcloud/application_default_credentials.json")

    let _ = resolveADCPath(environment: env)
    // We can't strictly test `resolveADCPath` with `isWindows` injected easily without changing its signature,
    // but we verify well-known path generation logic directly.
  }

  @Test("ADC well-known path Windows no APPDATA", .disabled("Unimplemented"))
  func testADCWellKnownPathWindowsNoAppData() {
    let env: [String: String] = [:]
    let path = resolveWellKnownADCPath(environment: env, isWindows: true)
    #expect(path == nil)
  }

  @Test("ADC well-known path POSIX", .disabled("Unimplemented"))
  func testADCWellKnownPathPOSIX() {
    let env = ["HOME": "/home/foo"]
    let path = resolveWellKnownADCPath(environment: env, isWindows: false)
    #expect(path?.path == "/home/foo/.config/gcloud/application_default_credentials.json")
  }

  @Test("ADC well-known path POSIX no HOME", .disabled("Unimplemented"))
  func testADCWellKnownPathPOSIXNoHome() {
    let env: [String: String] = [:]
    let path = resolveWellKnownADCPath(environment: env, isWindows: false)
    #expect(path == nil)
  }

  @Test("ADC path from environment", .disabled("Unimplemented"))
  func testADCPathFromEnv() {
    let env = [
      "GOOGLE_APPLICATION_CREDENTIALS": "/foo/bar.json"
    ]
    let path = resolveADCPath(environment: env)
    #expect(path == .environmentVariable(URL(fileURLWithPath: "/foo/bar.json")))
  }
}
