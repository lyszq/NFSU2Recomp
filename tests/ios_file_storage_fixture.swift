import CryptoKit
import Foundation

private var fixtureSessionState: Int32 = 0

// Explicit test boundary for the production lifecycle query. The product target
// resolves this name from NFSU2GameSession.h instead.
func nfs_game_session_get_state() -> Int32 {
    fixtureSessionState
}

private struct FixtureFailure: Error, CustomStringConvertible {
    let description: String
}

private func expect(_ condition: @autoclosure () -> Bool, _ message: String) throws {
    guard condition() else { throw FixtureFailure(description: message) }
}

private func expectFailure(_ operation: () throws -> Void, _ message: String) throws {
    do {
        try operation()
    } catch {
        return
    }
    throw FixtureFailure(description: message)
}

private func write(_ data: Data, to url: URL) throws {
    try FileManager.default.createDirectory(at: url.deletingLastPathComponent(),
                                            withIntermediateDirectories: true)
    try data.write(to: url, options: .atomic)
}

private func data(at url: URL) throws -> Data {
    try Data(contentsOf: url)
}

private func expectData(at url: URL, equals expected: Data, _ message: String) throws {
    let actual = try data(at: url)
    try expect(actual == expected, message)
}

private func sha256(_ data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}

private func makeExecutable() -> Data {
    Data("synthetic NFSU2 test executable bytes".utf8)
}

private func testDocumentsBootstrap(at root: URL) throws {
    let documents = root.appendingPathComponent("documents", isDirectory: true)
    let importFolder = documents.appendingPathComponent("Game Import", isDirectory: true)
    let guide = documents.appendingPathComponent("NFSU2 Import Guide.txt")

    try bootstrapSharedDocuments(at: documents)
    var isDirectory: ObjCBool = false
    try expect(FileManager.default.fileExists(atPath: importFolder.path, isDirectory: &isDirectory)
               && isDirectory.boolValue, "Documents/Game Import was not created")
    try expect(FileManager.default.fileExists(atPath: guide.path), "Files guide was not created at Documents root")
    try expect(!FileManager.default.fileExists(atPath: importFolder.appendingPathComponent(guide.lastPathComponent).path),
               "The guide was placed inside Game Import and could be counted as game data")

    let privateGameRoot = root.appendingPathComponent("Application Support/NFSU2/Game", isDirectory: true)
    try write(makeExecutable(), to: privateGameRoot.appendingPathComponent("SPEED2.EXE"))
    try write(Data("one synthetic game asset".utf8), to: privateGameRoot.appendingPathComponent("asset.dat"))
    try expect(countGameAssetFiles(at: privateGameRoot) == 1,
               "The Files guide affected the private game asset count")

    let originalGuide = Data("user-edited guide".utf8)
    try originalGuide.write(to: guide, options: .atomic)
    try bootstrapSharedDocuments(at: documents)
    try expectData(at: guide, equals: originalGuide, "A later bootstrap overwrote the user's guide")
}

private func testMergePreservesAndCopies(at root: URL) throws -> Int {
    let expectedExecutable = makeExecutable()
    let expectedHash = sha256(expectedExecutable)
    let source = root.appendingPathComponent("source", isDirectory: true)
    let destination = root.appendingPathComponent("Application Support/NFSU2/Game", isDirectory: true)

    let oldPrivateExecutable = expectedExecutable
    let oldAsset = Data("keep original asset".utf8)
    try write(expectedExecutable, to: source.appendingPathComponent("SPEED2.EXE"))
    try write(Data("new nested file".utf8), to: source.appendingPathComponent("assets/new.bin"))
    try write(Data("incoming conflict".utf8), to: source.appendingPathComponent("assets/shared.bin"))
    try write(Data("new root file".utf8), to: source.appendingPathComponent("root.dat"))

    try write(oldPrivateExecutable, to: destination.appendingPathComponent("SPEED2.EXE"))
    try write(oldAsset, to: destination.appendingPathComponent("assets/shared.bin"))
    try write(Data("existing unrelated asset".utf8), to: destination.appendingPathComponent("existing.dat"))

    let summary = try mergeGameAssetFolder(from: source, to: destination,
        expectedSize: expectedExecutable.count, expectedSHA256: expectedHash)
    try expect(summary.copied == 2, "Expected two new source files to be copied")
    try expect(summary.kept == 1, "Expected the existing conflicting asset to be kept")
    try expect(summary.total == 4, "The staged asset count should exclude SPEED2.EXE")
    try expectData(at: destination.appendingPathComponent("SPEED2.EXE"), equals: oldPrivateExecutable,
                   "The existing private executable was overwritten")
    try expectData(at: destination.appendingPathComponent("assets/shared.bin"), equals: oldAsset,
                   "An existing asset was overwritten")
    try expectData(at: destination.appendingPathComponent("assets/new.bin"), equals: Data("new nested file".utf8),
                   "A nested missing asset was not copied")
    try expect(countGameAssetFiles(at: destination) == 4,
               "The game asset count included the executable or missed a copied file")
    return summary.total
}

private func testInvalidExecutableLeavesPrivateDataUntouched(at root: URL) throws {
    let expectedExecutable = makeExecutable()
    let expectedHash = sha256(expectedExecutable)
    let source = root.appendingPathComponent("source", isDirectory: true)
    let destination = root.appendingPathComponent("Application Support/NFSU2/Game", isDirectory: true)
    let existingExecutable = expectedExecutable
    let existingAsset = Data("preserved asset fixture".utf8)
    let incomingAsset = Data("must not be copied".utf8)
    let wrongHashExecutable = Data(repeating: 0x42, count: expectedExecutable.count)
    let wrongHash = String(repeating: "0", count: 64)

    try write(expectedExecutable, to: destination.appendingPathComponent("SPEED2.EXE"))
    try write(existingAsset, to: destination.appendingPathComponent("existing.dat"))
    try write(wrongHashExecutable, to: source.appendingPathComponent("SPEED2.EXE"))
    try write(incomingAsset, to: source.appendingPathComponent("new.dat"))

    try expectFailure({
        _ = try mergeGameAssetFolder(from: source, to: destination,
            expectedSize: expectedExecutable.count,
            expectedSHA256: expectedHash)
    }, "A same-sized wrong-hash executable was accepted")
    try expectData(at: destination.appendingPathComponent("SPEED2.EXE"), equals: existingExecutable,
                   "Hash failure changed the existing private executable")
    try expectData(at: destination.appendingPathComponent("existing.dat"), equals: existingAsset,
                   "Hash failure changed an existing asset")
    try expect(!FileManager.default.fileExists(atPath: destination.appendingPathComponent("new.dat").path),
               "Hash failure copied assets before authenticating SPEED2.EXE")

    try write(expectedExecutable, to: source.appendingPathComponent("SPEED2.EXE"))
    try expectFailure({
        _ = try mergeGameAssetFolder(from: source, to: destination,
            expectedSize: expectedExecutable.count + 1, expectedSHA256: wrongHash)
    }, "An executable with the wrong expected size was accepted")
    try expectData(at: destination.appendingPathComponent("SPEED2.EXE"), equals: existingExecutable,
                   "Size failure changed the existing private executable")
    try expectData(at: destination.appendingPathComponent("existing.dat"), equals: existingAsset,
                   "Size failure changed an existing asset")
    try expect(!FileManager.default.fileExists(atPath: destination.appendingPathComponent("new.dat").path),
               "Size failure copied assets before authenticating SPEED2.EXE")
}

private func testSharedFolderDiscovery(at root: URL) throws {
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    let empty = try findSharedGameFolder(in: root)
    try expect(empty == nil, "An empty Files handoff should not select a game folder")
    let first = root.appendingPathComponent("My Game", isDirectory: true)
    try write(makeExecutable(), to: first.appendingPathComponent("SPEED2.EXE"))
    let selected = try findSharedGameFolder(in: root)
    try expect(selected?.path == first.path, "A complete folder copied under Game Import should be discovered")
    let second = root.appendingPathComponent("Other Game", isDirectory: true)
    try write(makeExecutable(), to: second.appendingPathComponent("SPEED2.EXE"))
    try expectFailure({ _ = try findSharedGameFolder(in: root) },
                      "Multiple candidate game folders should request a clear choice")
    try write(makeExecutable(), to: root.appendingPathComponent("SPEED2.EXE"))
    let direct = try findSharedGameFolder(in: root)
    try expect(direct?.path == root.path, "Direct EXE and asset placement should select Game Import itself")
}

private func testSymbolicLinksAreSkipped(at root: URL) throws {
    let executable = makeExecutable()
    let source = root.appendingPathComponent("source", isDirectory: true)
    let destination = root.appendingPathComponent("destination", isDirectory: true)
    let outside = root.appendingPathComponent("outside-secret.bin")
    let link = source.appendingPathComponent("linked.bin")
    try write(executable, to: source.appendingPathComponent("SPEED2.EXE"))
    try write(Data("safe regular asset".utf8), to: source.appendingPathComponent("regular.bin"))
    try write(Data("external target".utf8), to: outside)
    try FileManager.default.createSymbolicLink(at: link, withDestinationURL: outside)

    let summary = try mergeGameAssetFolder(from: source, to: destination,
        expectedSize: executable.count, expectedSHA256: sha256(executable))
    try expect(summary.total == 1, "The symlink was counted as a game asset")
    try expect(!FileManager.default.fileExists(atPath: destination.appendingPathComponent("linked.bin").path),
               "The symlink target was copied into the game folder")
}

@main
struct IOSFileStorageFixture {
    static func main() throws {
        guard CommandLine.arguments.count == 2 else {
            throw FixtureFailure(description: "Expected one temporary fixture root argument")
        }
        let root = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)

        fixtureSessionState = 0
        try expect(runtimeSessionAllowsStorageMutation(), "An idle test session should allow storage operations")
        fixtureSessionState = 2
        try expect(!runtimeSessionAllowsStorageMutation(), "A running test session should block storage operations")
        fixtureSessionState = 0

        try testDocumentsBootstrap(at: root.appendingPathComponent("documents-case", isDirectory: true))
        let assetCount = try testMergePreservesAndCopies(at: root.appendingPathComponent("merge-case", isDirectory: true))
        try testInvalidExecutableLeavesPrivateDataUntouched(at: root.appendingPathComponent("invalid-case", isDirectory: true))
        try testSymbolicLinksAreSkipped(at: root.appendingPathComponent("symlink-case", isDirectory: true))
        try testSharedFolderDiscovery(at: root.appendingPathComponent("discovery-case", isDirectory: true))

        print("PASS: Files bootstrap, existing-data preservation, hash/size rejection, nested copies, symlink skipping, and session-state guard (\(assetCount) staged assets).")
    }
}
