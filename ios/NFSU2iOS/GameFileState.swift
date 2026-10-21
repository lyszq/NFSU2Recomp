import Combine
import CryptoKit
import Foundation

private func mergeGameAssetFolder(from source: URL, to destination: URL,
                                  expectedSize: Int, expectedSHA256: String) throws -> (copied: Int, kept: Int, total: Int) {
    let manager = FileManager.default
    var isDirectory: ObjCBool = false
    guard manager.fileExists(atPath: source.path, isDirectory: &isDirectory), isDirectory.boolValue else {
        throw NSError(domain: "NFSU2", code: 10,
            userInfo: [NSLocalizedDescriptionKey: "Select the full game folder, not an archive or a single asset folder."])
    }

    let sourceExecutable = source.appendingPathComponent("SPEED2.EXE")
    let executableData = try Data(contentsOf: sourceExecutable)
    let executableHash = SHA256.hash(data: executableData).map { String(format: "%02x", $0) }.joined()
    guard executableData.count == expectedSize, executableHash == expectedSHA256 else {
        throw NSError(domain: "NFSU2", code: 11,
            userInfo: [NSLocalizedDescriptionKey: "The selected game folder must contain the same verified SPEED2.EXE build."])
    }

    try manager.createDirectory(at: destination, withIntermediateDirectories: true)
    guard let enumerator = manager.enumerator(at: source,
            includingPropertiesForKeys: [.isDirectoryKey, .isRegularFileKey, .isSymbolicLinkKey],
            options: [.skipsHiddenFiles]) else {
        throw NSError(domain: "NFSU2", code: 12,
            userInfo: [NSLocalizedDescriptionKey: "Could not enumerate the selected game folder."])
    }

    var copied = 0
    var kept = 0
    for case let item as URL in enumerator {
        let values = try item.resourceValues(forKeys: [.isDirectoryKey, .isRegularFileKey, .isSymbolicLinkKey])
        if values.isSymbolicLink == true {
            enumerator.skipDescendants()
            continue
        }
        let relative = String(item.path.dropFirst(source.path.count + 1))
        guard !relative.isEmpty, !relative.hasPrefix("/"),
              !relative.split(separator: "/").contains("..") else { continue }
        if relative.caseInsensitiveCompare("SPEED2.EXE") == .orderedSame { continue }

        let target = destination.appendingPathComponent(relative)
        if values.isDirectory == true {
            try manager.createDirectory(at: target, withIntermediateDirectories: true)
        } else if values.isRegularFile == true {
            if manager.fileExists(atPath: target.path) {
                kept += 1
                continue
            }
            try manager.createDirectory(at: target.deletingLastPathComponent(), withIntermediateDirectories: true)
            try manager.copyItem(at: item, to: target)
            copied += 1
        }
    }

    let total = countGameAssetFiles(at: destination)
    guard total > 0 else {
        throw NSError(domain: "NFSU2", code: 13,
            userInfo: [NSLocalizedDescriptionKey: "The selected folder contained no game data files beside SPEED2.EXE."])
    }
    return (copied, kept, total)
}

private func countGameAssetFiles(at root: URL) -> Int {
    guard let enumerator = FileManager.default.enumerator(at: root,
            includingPropertiesForKeys: [.isRegularFileKey, .isSymbolicLinkKey],
            options: [.skipsHiddenFiles]) else { return 0 }
    var count = 0
    for case let item as URL in enumerator {
        guard item.lastPathComponent.caseInsensitiveCompare("SPEED2.EXE") != .orderedSame,
              let values = try? item.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey]),
              values.isRegularFile == true, values.isSymbolicLink != true else { continue }
        count += 1
    }
    return count
}

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
    @Published private(set) var gameAssetFileCount = 0
    @Published private(set) var assetImportRunning = false
    @Published var assetImportMessage = "Import the full game folder to stage assets in the app sandbox."
    var hasGameAssets: Bool { gameAssetFileCount > 0 }

    @Published private(set) var probeRunning = false
    @Published private(set) var probePassed = false
    @Published private(set) var probeOutput = "Not run. Load the verified EXE to test the real image."

    private static var savedExecutable: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("NFSU2/Game/SPEED2.EXE")
    }

    var executablePath: String { Self.savedExecutable.path }
    var assetRootPath: String { Self.savedExecutable.deletingLastPathComponent().path }
    var saveRootPath: String {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("NFSU2/Saves", isDirectory: true).path
    }

    func runImageProbe() {
#if NFS_FULL_RUNTIME
        probePassed = false
        probeOutput = "The full-runtime build uses a persistent game session; the bounded image probe is available in the diagnostic build."
#else
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
#endif
    }

    init() {
        gameAssetFileCount = countGameAssetFiles(at: Self.savedExecutable.deletingLastPathComponent())
        let saved = Self.savedExecutable
        guard let data = try? Data(contentsOf: saved),
              data.count == Self.expectedSize else { return }
        let digest = SHA256.hash(data: data)
            .map { String(format: "%02x", $0) }
            .joined()
        if digest == Self.expectedSHA256 {
            isVerified = true
#if NFS_FULL_RUNTIME
            message = "Previously verified SPEED2.EXE is still saved locally. Full runtime can start; game assets must also be present in the app game folder."
#else
            message = "Previously verified SPEED2.EXE is still saved locally. Ready for native image diagnostics; full game boot is pending."
#endif
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
            // Keep the authenticated runtime input app-local and stable.
            try data.write(to: destination, options: .atomic)
            isVerified = true
            gameAssetFileCount = countGameAssetFiles(at: folder)
#if NFS_FULL_RUNTIME
            message = "Supported executable verified and saved locally. Full runtime can start; assets are resolved beside the saved executable."
#else
            message = "Supported executable verified and saved locally. Ready for native image diagnostics; full game boot is pending."
#endif
        } catch {
            message = "Could not read or save executable: \(error.localizedDescription)"
        }
    }

    func importGameAssets(from source: URL) {
        guard isVerified, !assetImportRunning else { return }
        assetImportRunning = true
        assetImportMessage = "Checking the selected game folder and copying assets into the app sandbox…"
        let accessGranted = source.startAccessingSecurityScopedResource()
        let destination = Self.savedExecutable.deletingLastPathComponent()
        let expectedSize = Self.expectedSize
        let expectedSHA256 = Self.expectedSHA256

        Self.runtimeQueue.async {
            defer { if accessGranted { source.stopAccessingSecurityScopedResource() } }
            let result: Result<(copied: Int, kept: Int, total: Int), Error>
            do {
                result = .success(try mergeGameAssetFolder(from: source, to: destination,
                    expectedSize: expectedSize, expectedSHA256: expectedSHA256))
            } catch {
                result = .failure(error)
            }
            let count = countGameAssetFiles(at: destination)
            DispatchQueue.main.async {
                self.gameAssetFileCount = count
                self.assetImportRunning = false
                switch result {
                case .success(let summary):
                    self.assetImportMessage = "Staged \(summary.copied) files; kept \(summary.kept) existing files. \(summary.total) game data files are present in the sandbox."
                case .failure(let error):
                    self.assetImportMessage = "Asset import failed: \(error.localizedDescription)"
                }
            }
        }
    }
}
