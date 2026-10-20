import Combine
import CryptoKit
import Foundation

/// Checks the one PC executable accepted by the upstream macOS recompilation.
/// Never places proprietary binaries into git or the build artifact.
@MainActor
final class GameFileState: ObservableObject {
    static let expectedSize = 4_788_224
    static let expectedSHA256 = "8f6a9ae2c4cfa01181d2fd755d99c6f4b7103f60273908ea1de1e719dfe2a297"

    @Published var message = "No executable selected."
    @Published private(set) var isVerified = false

    func importExecutable(from url: URL) {
        isVerified = false
        let accessGranted = url.startAccessingSecurityScopedResource()
        defer { if accessGranted { url.stopAccessingSecurityScopedResource() } }

        guard url.lastPathComponent.caseInsensitiveCompare("SPEED2.EXE") == .orderedSame else {
            message = "Select the file named SPEED2.EXE, not a game archive or folder."
            return
        }
        do {
            let data = try Data(contentsOf: url)
            guard data.count == Self.expectedSize else {
                message = "Unsupported SPEED2.EXE size: \(data.count) bytes (expected \(Self.expectedSize))."
                return
            }
            let sha = SHA256.hash(data: data)
                .map { String(format: "%02x", $0) }
                .joined()
            guard sha == Self.expectedSHA256 else {
                message = "File size matched but SHA-256 did not: \(sha)"
                return
            }

            let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            let folder = base.appendingPathComponent("NFSU2/Game", isDirectory: true)
            try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
            let destination = folder.appendingPathComponent("SPEED2.EXE")
            // Save an app-local copy for future game-runtime integration.
            try data.write(to: destination, options: .atomic)
            isVerified = true
            message = "Supported executable verified and saved locally. Runtime integration is still pending."
        } catch {
            message = "Could not read or save executable: \(error.localizedDescription)"
        }
    }
}
