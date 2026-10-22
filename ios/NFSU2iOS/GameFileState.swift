import Combine
import CryptoKit
import Foundation

private func authenticatedGameExecutable(at url: URL, expectedSize: Int,
                                        expectedSHA256: String) throws -> Data {
    guard let values = try? url.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey]),
          values.isRegularFile == true, values.isSymbolicLink != true else {
        throw NSError(domain: "NFSU2", code: 11,
            userInfo: [NSLocalizedDescriptionKey: "The selected SPEED2.EXE must be a regular file, not a link."])
    }
    let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
    guard (attributes[.size] as? NSNumber)?.intValue == expectedSize else {
        throw NSError(domain: "NFSU2", code: 11,
            userInfo: [NSLocalizedDescriptionKey: "The selected game folder must contain the same verified SPEED2.EXE build."])
    }
    let data = try Data(contentsOf: url)
    let executableHash = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    guard data.count == expectedSize, executableHash == expectedSHA256 else {
        throw NSError(domain: "NFSU2", code: 11,
            userInfo: [NSLocalizedDescriptionKey: "The selected game folder must contain the same verified SPEED2.EXE build."])
    }
    return data
}

private func mergeGameAssetFolder(from source: URL, to destination: URL,
                                  expectedSize: Int, expectedSHA256: String,
                                  requireAssetFiles: Bool = true) throws -> (copied: Int, kept: Int, total: Int) {
    let manager = FileManager.default
    var isDirectory: ObjCBool = false
    guard manager.fileExists(atPath: source.path, isDirectory: &isDirectory), isDirectory.boolValue else {
        throw NSError(domain: "NFSU2", code: 10,
            userInfo: [NSLocalizedDescriptionKey: "Select the full game folder, not an archive or a single asset folder."])
    }

    let sourceExecutable = source.appendingPathComponent("SPEED2.EXE")
    _ = try authenticatedGameExecutable(at: sourceExecutable,
                                        expectedSize: expectedSize,
                                        expectedSHA256: expectedSHA256)

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
    guard !requireAssetFiles || total > 0 else {
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

private func findSharedGameFolder(in importRoot: URL) throws -> URL? {
    let manager = FileManager.default
    var rootIsDirectory: ObjCBool = false
    guard manager.fileExists(atPath: importRoot.path,
                             isDirectory: &rootIsDirectory),
          rootIsDirectory.boolValue else { return nil }

    let executableName = "SPEED2.EXE"
    let directExecutable = importRoot.appendingPathComponent(executableName)
    if manager.fileExists(atPath: directExecutable.path) { return importRoot }

    let children = try manager.contentsOfDirectory(
        at: importRoot,
        includingPropertiesForKeys: [.isDirectoryKey, .isSymbolicLinkKey],
        options: [.skipsHiddenFiles])
    let candidates = children.filter { child in
        guard let values = try? child.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey]),
              values.isDirectory == true, values.isSymbolicLink != true else { return false }
        return manager.fileExists(atPath: child.appendingPathComponent(executableName).path)
    }
    guard candidates.count <= 1 else {
        throw NSError(domain: "NFSU2", code: 14,
            userInfo: [NSLocalizedDescriptionKey: "More than one game folder was found in Files/Game Import. Leave one complete game folder there, then check again."])
    }
    return candidates.first
}

private func runtimeSessionAllowsStorageMutation() -> Bool {
#if NFS_FULL_RUNTIME
    // NFS_GAME_SESSION_IDLE is defined as zero in NFSU2GameSession.h.
    return nfs_game_session_get_state() == 0
#else
    return true
#endif
}

private func bootstrapSharedDocuments(at documentsRoot: URL) throws {
    let manager = FileManager.default
    let importFolder = documentsRoot.appendingPathComponent("Game Import", isDirectory: true)
    let guideURL = documentsRoot.appendingPathComponent("NFSU2 Import Guide.txt")
    try manager.createDirectory(at: importFolder, withIntermediateDirectories: true)
    guard !manager.fileExists(atPath: guideURL.path) else { return }

    let guide = """
    NFSU2 iOS game-file import

    In Files, open On My iPad > NFSU2 iOS > Game Import. Copy the complete game folder there, or copy SPEED2.EXE and its game-data folders directly into Game Import.

    Open NFSU2 iOS and use “CHECK FILES FOLDER”. The app accepts only the supported SPEED2.EXE build, then copies missing game files into its private working folder. Existing private game files are kept.

    The app keeps its working game copy and save data in private Application Support storage. This Files folder is only an import handoff. File counts do not confirm that the game data is complete.
    """
    try Data(guide.utf8).write(to: guideURL, options: .atomic)
}

/// Checks the one PC executable accepted by the upstream macOS recompilation.
/// Never places proprietary binaries into git or the build artifact.
@MainActor
final class GameFileState: ObservableObject {
    // Serializes native probes, game-file imports, and full runtime startup.
    nonisolated static let runtimeQueue = DispatchQueue(label: "dev.lyszq.nfsu2ios.runtime", qos: .userInitiated)
    nonisolated static let expectedSize = 4_788_224
    nonisolated static let expectedSHA256 = "8f6a9ae2c4cfa01181d2fd755d99c6f4b7103f60273908ea1de1e719dfe2a297"

    @Published var message = "No executable selected."
    @Published private(set) var isVerified = false
    @Published private(set) var gameAssetFileCount = 0
    @Published private(set) var assetImportRunning = false
    @Published var assetImportMessage = "Import the full game folder to stage assets in the app sandbox."
    var hasGameAssets: Bool { gameAssetFileCount > 0 }

    private var localAssetCountReady = false
    private var sharedImportRefreshPending = false

    @Published private(set) var probeRunning = false
    @Published private(set) var probePassed = false
    @Published private(set) var probeOutput = "Not run. Load the verified EXE to test the real image."

    private static var savedExecutable: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("NFSU2/Game/SPEED2.EXE")
    }

    private static var documentsRoot: URL {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
    }

    private static var sharedImportFolder: URL {
        documentsRoot.appendingPathComponent("Game Import", isDirectory: true)
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
        guard isVerified, !probeRunning, !assetImportRunning else { return }
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
        let documentsReady: Bool
        do {
            try bootstrapSharedDocuments(at: Self.documentsRoot)
            documentsReady = true
        } catch {
            documentsReady = false
            assetImportMessage = "Could not prepare the Files import folder: \(error.localizedDescription)"
        }

        let saved = Self.savedExecutable
        if (try? authenticatedGameExecutable(at: saved,
                                             expectedSize: Self.expectedSize,
                                             expectedSHA256: Self.expectedSHA256)) != nil {
            isVerified = true
#if NFS_FULL_RUNTIME
            message = "Previously verified SPEED2.EXE is still saved locally. Full runtime can start; game assets must also be present in the app game folder."
#else
            message = "Previously verified SPEED2.EXE is still saved locally. Ready for native image diagnostics; full game boot is pending."
#endif
        }

        let assetRoot = saved.deletingLastPathComponent()
        Self.runtimeQueue.async {
            let count = countGameAssetFiles(at: assetRoot)
            DispatchQueue.main.async {
                self.gameAssetFileCount = count
                self.localAssetCountReady = true
                if documentsReady && (self.sharedImportRefreshPending || !self.isVerified || count == 0) {
                    self.sharedImportRefreshPending = false
                    self.refreshSharedImport()
                }
            }
        }
    }

    func importExecutable(from url: URL) {
        guard !assetImportRunning, !probeRunning else {
            message = "Wait for the current game-file operation to finish before selecting SPEED2.EXE."
            return
        }
        guard runtimeSessionAllowsStorageMutation() else {
            message = "The executable cannot be changed after the persistent game session starts."
            return
        }
        assetImportRunning = true
        defer { assetImportRunning = false }
        let accessGranted = url.startAccessingSecurityScopedResource()
        defer { if accessGranted { url.stopAccessingSecurityScopedResource() } }

        guard url.lastPathComponent.caseInsensitiveCompare("SPEED2.EXE") == .orderedSame else {
            message = "Select the file named SPEED2.EXE, not a game archive or folder."
            return
        }
        do {
            let data = try authenticatedGameExecutable(at: url,
                                                       expectedSize: Self.expectedSize,
                                                       expectedSHA256: Self.expectedSHA256)

            let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            let folder = base.appendingPathComponent("NFSU2/Game", isDirectory: true)
            try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
            let destination = folder.appendingPathComponent("SPEED2.EXE")
            // Preserve an already verified private runtime input byte-for-byte.
            guard runtimeSessionAllowsStorageMutation() else {
                message = "The game session started before SPEED2.EXE could be saved; the private copy was left unchanged."
                return
            }
            if (try? authenticatedGameExecutable(at: destination,
                                                 expectedSize: Self.expectedSize,
                                                 expectedSHA256: Self.expectedSHA256)) == nil {
                try data.write(to: destination, options: .atomic)
            }
            isVerified = true
#if NFS_FULL_RUNTIME
            message = "Supported executable verified and saved locally. Full runtime can start; assets are resolved beside the saved executable."
#else
            message = "Supported executable verified and saved locally. Ready for native image diagnostics; full game boot is pending."
#endif
            Self.runtimeQueue.async {
                let count = countGameAssetFiles(at: folder)
                DispatchQueue.main.async { self.gameAssetFileCount = count }
            }
        } catch {
            message = "Could not read or save executable: \(error.localizedDescription)"
        }
    }

    /// Imports a user-staged Files folder without changing the private runtime paths.
    /// Automatic checks skip once a verified executable and local assets already exist;
    /// force a check from an explicit user action to merge later additions.
    func refreshSharedImport(force: Bool = false) {
        guard !assetImportRunning, !probeRunning else { return }
        guard runtimeSessionAllowsStorageMutation() else {
            assetImportMessage = "Files imports are unavailable after the persistent game session starts."
            return
        }
        guard localAssetCountReady || force else {
            sharedImportRefreshPending = true
            return
        }
        if !force && isVerified && hasGameAssets { return }

        do {
            try bootstrapSharedDocuments(at: Self.documentsRoot)
        } catch {
            assetImportMessage = "Could not prepare the Files import folder: \(error.localizedDescription)"
            return
        }

        assetImportRunning = true
        assetImportMessage = "Checking the Files game-import folder…"
        let sourceRoot = Self.sharedImportFolder
        let destination = Self.savedExecutable.deletingLastPathComponent()
        let destinationExecutable = Self.savedExecutable
        let expectedSize = Self.expectedSize
        let expectedSHA256 = Self.expectedSHA256

        Self.runtimeQueue.async {
            let result: Result<(copied: Int, kept: Int, total: Int), Error>
            do {
                guard runtimeSessionAllowsStorageMutation() else {
                    throw NSError(domain: "NFSU2", code: 16,
                        userInfo: [NSLocalizedDescriptionKey: "The game session started before the Files import could run. No files were changed."])
                }
                guard let source = try findSharedGameFolder(in: sourceRoot) else {
                    throw NSError(domain: "NFSU2", code: 15,
                        userInfo: [NSLocalizedDescriptionKey: "No SPEED2.EXE was found in Files/Game Import. Copy the complete game folder there, then check again."])
                }

                let sourceExecutable = source.appendingPathComponent("SPEED2.EXE")
                let incomingData = try authenticatedGameExecutable(at: sourceExecutable,
                    expectedSize: expectedSize, expectedSHA256: expectedSHA256)
                let manager = FileManager.default
                if manager.fileExists(atPath: destinationExecutable.path) {
                    // Never replace an existing private executable; confirm it is still the accepted build.
                    _ = try authenticatedGameExecutable(at: destinationExecutable,
                        expectedSize: expectedSize, expectedSHA256: expectedSHA256)
                } else {
                    try manager.createDirectory(at: destination, withIntermediateDirectories: true)
                    try incomingData.write(to: destinationExecutable, options: .atomic)
                }

                let summary = try mergeGameAssetFolder(from: source, to: destination,
                    expectedSize: expectedSize, expectedSHA256: expectedSHA256,
                    requireAssetFiles: false)
                result = .success((summary.copied, summary.kept, summary.total))
            } catch {
                result = .failure(error)
            }

            let count = countGameAssetFiles(at: destination)
            let savedExecutable = (try? authenticatedGameExecutable(at: destinationExecutable,
                expectedSize: expectedSize, expectedSHA256: expectedSHA256)) != nil
            DispatchQueue.main.async {
                self.gameAssetFileCount = count
                self.isVerified = savedExecutable
                self.assetImportRunning = false
                switch result {
                case .success(let summary):
                    self.assetImportMessage = "Files check complete: copied \(summary.copied) missing files and kept \(summary.kept) existing files. \(summary.total) game data files are staged; the count does not confirm completeness."
                    if savedExecutable {
#if NFS_FULL_RUNTIME
                        self.message = "Supported SPEED2.EXE is verified in private storage. Full runtime can start when its required game data is present."
#else
                        self.message = "Supported SPEED2.EXE is verified in private storage. Ready for native image diagnostics."
#endif
                    }
                case .failure(let error):
                    self.assetImportMessage = "Files import check failed: \(error.localizedDescription)"
                    if savedExecutable {
#if NFS_FULL_RUNTIME
                        self.message = "Previously verified SPEED2.EXE is still saved locally. Game data import needs attention."
#else
                        self.message = "Previously verified SPEED2.EXE is still saved locally."
#endif
                    }
                }
            }
        }
    }

    func importGameAssets(from source: URL) {
        guard isVerified, !assetImportRunning, !probeRunning else { return }
        guard runtimeSessionAllowsStorageMutation() else {
            assetImportMessage = "Files imports are unavailable after the persistent game session starts."
            return
        }
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
                guard runtimeSessionAllowsStorageMutation() else {
                    throw NSError(domain: "NFSU2", code: 16,
                        userInfo: [NSLocalizedDescriptionKey: "The game session started before the selected-folder import could run. No files were changed."])
                }
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
