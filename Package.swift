// swift-tools-version: 6.2
//
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

import PackageDescription

let package = Package(
  name: "GoogleCloudAuth",
  platforms: [
    .macOS(.v15)
  ],
  products: [
    .library(name: "GoogleCloudAuth", targets: ["GoogleCloudAuth"])
  ],
  dependencies: [
    .package(url: "https://github.com/apple/swift-system.git", from: "1.0.0"),
    .package(url: "https://github.com/vapor/jwt-kit.git", from: "5.0.0")
  ],

  targets: [
    .target(
      name: "GoogleCloudAuth",
      dependencies: [
        "RustAuthCoreBridge",
        .product(name: "SystemPackage", package: "swift-system"),
        .product(name: "JWTKit", package: "jwt-kit")
      ]
    ),
    .target(
      name: "RustAuthCoreBridge",
      dependencies: ["RustAuthCoreFFI"],
      swiftSettings: [.swiftLanguageMode(.v5)]
    ),
    .target(
      name: "RustAuthCoreFFI",
      linkerSettings: [
        .linkedLibrary("rust_auth_core"),
        .unsafeFlags(["-L", "\(Context.packageDirectory)/../../target/release"]),
      ]
    ),
    .testTarget(
      name: "GoogleCloudAuthTests",
      dependencies: ["GoogleCloudAuth", .product(name: "JWTKit", package: "jwt-kit")],
      path: "Tests"),
  ]
)
