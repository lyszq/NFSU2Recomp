import Combine
import CryptoKit
import Foundation

/// Checks the one PC executable accepted by the upstream macOS recompilation.
/// Never places proprietary binaries into git or the build artifact.
@MainActor
final class GameFileState: ObservableObject {
    // Serial ownership for all native probe mapping/teardown, including multiple views.
    nonisolated static let runtimeQueue = DispatchQueue(label: "dev.lyszq.nfsu2ios.runtime", qos: .userInitiated)
    nonisolated static let expectedSize = 4_788_224
    nonisolated static let expectedSHA256 = "8f6a9ae2c4cfa01181d2fd755d99c6f4b7103f60273908ea1de1e719dfe2a297"

    @Published var message = "No executable selected."
    @Published private(set) var isVerified = false

    @Published private(set) var probeRunning = false
    @Published private(set) var probePassed = false
    @Published private(set) var probeOutput = "Not run. Load the verified EXE to test the real image."

    private static var savedExecutable: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("NFSU2/Game/SPEED2.EXE")
    }

    func runImageProbe() {
        guard isVerified, !probeRunning else { return }
        probeRunning = true
        probePassed = false
        probeOutput = "Verifying saved EXE and loading its PE32 image..."
        let saved = Self.savedExecutable
        // Reauthenticate the exact bytes passed to C, on the worker queue.
        // No sandbox path or proprietary bytes are sent to CI or diagnostics.
        Self.runtimeQueue.async {
            var output: String
            var passed = false
            do {
                let attributes = try FileManager.default.attributesOfItem(atPath: saved.path)
                guard (attributes[.size] as? NSNumber)?.intValue == Self.expectedSize else {
                    throw NSError(domain: "NFSU2", code: 1,
                        userInfo: [NSLocalizedDescriptionKey: "Saved EXE has an unsupported size."])
                }
                let data = try Data(contentsOf: saved)
                let sha = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
                guard data.count == Self.expectedSize, sha == Self.expectedSHA256 else {
                    throw NSError(domain: "NFSU2", code: 2,
                        userInfo: [NSLocalizedDescriptionKey: "Saved EXE failed SHA-256 authentication."])
                }
                var buffer = [CChar](repeating: 0, count: 2048)
                let result = data.withUnsafeBytes { bytes in
                    buffer.withUnsafeMutableBufferPointer { diagnostic in
                        nfs_guest_image_probe(bytes.bindMemory(to: UInt8.self).baseAddress,
                                              bytes.count, diagnostic.baseAddress, diagnostic.count)
                    }
                }
                passed = result == 0
                output = String(cString: buffer)
            } catch {
                output = "FAIL | \(error.localizedDescription)"
            }
            let version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "?"
            output = "NFSU2 iOS \(version)\n" + output
            let finalPassed = passed
            let finalOutput = output
            DispatchQueue.main.async {
                self.probePassed = finalPassed
                self.probeOutput = finalOutput
                self.probeRunning = false
            }
        }
    }

    init() {
        let saved = Self.savedExecutable
        guard let data = try? Data(contentsOf: saved),
              data.count == Self.expectedSize else { return }
        let digest = SHA256.hash(data: data)
            .map { String(format: "%02x", $0) }
            .joined()
        if digest == Self.expectedSHA256 {
            isVerified = true
            message = "Previously verified SPEED2.EXE is still saved locally. Runtime integration is pending."
        }
    }

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
