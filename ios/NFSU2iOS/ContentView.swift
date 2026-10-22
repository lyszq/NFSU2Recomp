import SwiftUI
import UIKit

#if NFS_FULL_RUNTIME
struct ContentView: View {
    @EnvironmentObject private var files: GameFileState
    @State private var activeFileImport: GameFileSelectionRequest?

    private func completeFileImport(_ request: GameFileSelectionRequest,
                                    outcome: GameFileSelectionOutcome) {
        switch (request, outcome) {
        case (.executable, .selected(let url)):
            files.importExecutable(from: url)
        case (.gameFolder, .selected(let url)):
            files.importGameAssets(from: url)
        case (.executable, .failed(let error)):
            files.message = "File selection failed: \(error.localizedDescription)"
        case (.gameFolder, .failed(let error)):
            files.assetImportMessage = "Asset folder selection failed: \(error.localizedDescription)"
        case (_, .cancelled):
            break
        }
    }

    var body: some View {
        ZStack {
            Color.black.ignoresSafeArea()
            if files.isVerified && files.hasGameAssets {
                GameMetalView()
                    .environmentObject(files)
            } else if files.isVerified {
                VStack(spacing: 18) {
                    Image(systemName: "folder.badge.plus")
                        .font(.system(size: 42, weight: .bold))
                        .foregroundStyle(.mint)
                    Text("IMPORT GAME FOLDER")
                        .font(.system(.title2, design: .monospaced, weight: .black))
                        .foregroundStyle(.white)
                    Text("Choose the full game folder containing the same verified SPEED2.EXE and its asset directories, or copy it into Files › On My iPad › NFSU2 iOS › Game Import. The app copies game data into its sandbox and leaves the Files copy untouched.")
                        .font(.body)
                        .foregroundStyle(.white.opacity(0.72))
                        .multilineTextAlignment(.center)
                    Button {
                        activeFileImport = .gameFolder
                    } label: {
                        Label(files.assetImportRunning ? "IMPORTING GAME DATA…" : "IMPORT GAME FOLDER",
                              systemImage: files.assetImportRunning ? "hourglass" : "folder.badge.plus")
                            .fontWeight(.bold)
                            .frame(maxWidth: 360)
                            .padding(12)
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(.mint)
                    .disabled(files.assetImportRunning || activeFileImport != nil)
                    .accessibilityIdentifier("select-game-folder")
                    .accessibilityHint("Opens Files so you can select the full verified game folder.")
                    Button {
                        files.refreshSharedImport(force: true)
                    } label: {
                        Label(files.assetImportRunning ? "CHECKING FILES FOLDER…" : "CHECK FILES FOLDER",
                              systemImage: files.assetImportRunning ? "hourglass" : "folder")
                            .fontWeight(.semibold)
                    }
                    .buttonStyle(.bordered)
                    .tint(.mint)
                    .disabled(files.assetImportRunning || activeFileImport != nil)
                    .accessibilityIdentifier("check-game-files-folder")
                    .accessibilityHint("Checks Files, On My iPad, NFSU2 iOS, Game Import for the verified game folder.")
                    if files.assetImportRunning { ProgressView().tint(.mint) }
                    Text(files.assetImportMessage)
                        .font(.system(.footnote, design: .monospaced))
                        .foregroundStyle(.white.opacity(0.78))
                        .multilineTextAlignment(.center)
                        .textSelection(.enabled)
                        .frame(maxWidth: 560)
                    Text("The app checks SPEED2.EXE against the saved build and copies missing files. Asset completeness is not inferred from the file count.")
                        .font(.footnote)
                        .foregroundStyle(.white.opacity(0.55))
                        .multilineTextAlignment(.center)
                        .frame(maxWidth: 560)
                }
                .padding(28)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .background(Color(red: 0.045, green: 0.07, blue: 0.095))
            } else {
                VStack(spacing: 18) {
                    Image(systemName: "flag.checkered")
                        .font(.system(size: 44, weight: .bold))
                        .foregroundStyle(.mint)
                    Text("NFSU2 · FULL RUNTIME")
                        .font(.system(.title2, design: .monospaced, weight: .black))
                        .foregroundStyle(.white)
                    Text("In Files, choose the supported SPEED2.EXE. The app authenticates and stores its private copy in Application Support before starting the guest runtime.")
                        .font(.body)
                        .foregroundStyle(.white.opacity(0.72))
                        .multilineTextAlignment(.center)
                    Text("After verification, choose the full game folder or place it in Files › On My iPad › NFSU2 iOS › Game Import.")
                        .font(.footnote)
                        .foregroundStyle(.white.opacity(0.55))
                        .multilineTextAlignment(.center)
                    Button {
                        activeFileImport = .executable
                    } label: {
                        Label("SELECT SPEED2.EXE", systemImage: "doc.badge.plus")
                            .fontWeight(.bold)
                            .frame(maxWidth: 360)
                            .padding(12)
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(.mint)
                    .disabled(activeFileImport != nil)
                    .accessibilityIdentifier("select-game-executable")
                    .accessibilityHint("Opens Files so you can select the original SPEED2.EXE.")
                    Button {
                        files.refreshSharedImport(force: true)
                    } label: {
                        Label(files.assetImportRunning ? "CHECKING FILES FOLDER…" : "CHECK FILES FOLDER",
                              systemImage: files.assetImportRunning ? "hourglass" : "folder")
                    }
                    .buttonStyle(.bordered)
                    .tint(.mint)
                    .disabled(files.assetImportRunning || activeFileImport != nil)
                    .accessibilityIdentifier("check-game-files-folder")
                    Text(files.message)
                        .font(.system(.footnote, design: .monospaced))
                        .foregroundStyle(files.isVerified ? .mint : .white.opacity(0.7))
                        .textSelection(.enabled)
                        .frame(maxWidth: 520)
                    Text(files.assetImportMessage)
                        .font(.footnote)
                        .foregroundStyle(.white.opacity(0.65))
                        .multilineTextAlignment(.center)
                        .frame(maxWidth: 520)
                    Text("Game assets are resolved from the app sandbox game folder. Save data is written under Application Support/NFSU2/Saves. Starting the runtime does not confirm a visible game frame.")
                        .font(.footnote)
                        .foregroundStyle(.white.opacity(0.55))
                        .multilineTextAlignment(.center)
                        .frame(maxWidth: 520)
                }
                .padding(28)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .background(Color(red: 0.045, green: 0.07, blue: 0.095))
            }
        }
        .preferredColorScheme(.dark)
        .gameFileImporter(selection: $activeFileImport) { request, outcome in
            completeFileImport(request, outcome: outcome)
        }
    }
}
#else
struct ContentView: View {
    @EnvironmentObject private var files: GameFileState
    @Environment(\.isScrollEnabled) private var inheritedScrollEnabled
    @State private var activeFileImport: GameFileSelectionRequest?
    @State private var previewTouchActive = false
    @State private var smokeRunning = false
    @State private var smokePassed = false
    @State private var smokeOutput = "Not run yet. Tap RUN CPU + MEMORY TEST."

    private func startSmokeTest() {
        guard !smokeRunning, !files.probeRunning else { return }
        smokeRunning = true
        smokePassed = false
        smokeOutput = "Running native CPU and virtual-memory tests…"

        let version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "?"
        let device = "iOS \(version) | \(UIDevice.current.model) \(UIDevice.current.systemName) \(UIDevice.current.systemVersion)"
        // Reserving a large virtual address range is not work for the UI thread.
        GameFileState.runtimeQueue.async {
            var buffer = [CChar](repeating: 0, count: 1024)
            let result = buffer.withUnsafeMutableBufferPointer { ptr in
                nfs_guest_smoke_run(ptr.baseAddress, ptr.count)
            }
            let output = device + "\n" + String(cString: buffer)
            DispatchQueue.main.async {
                self.smokePassed = (result == 0)
                self.smokeOutput = output
                self.smokeRunning = false
            }
        }
    }

    private var imageProbePanel: some View {
        VStack(alignment: .leading, spacing: 10) {
            Button(action: files.runImageProbe) {
                Label(files.probeRunning ? "Loading image..." : "LOAD VERIFIED GAME IMAGE",
                      systemImage: "memorychip")
                    .frame(maxWidth: .infinity)
                    .padding(10)
            }
            .buttonStyle(.borderedProminent)
            .tint(.mint)
            .disabled(!files.isVerified || files.probeRunning || smokeRunning)
            Text(files.probeOutput)
                .font(.system(.footnote, design: .monospaced))
                .foregroundStyle(files.probePassed ? .mint : .white)
                .textSelection(.enabled)
            if !files.probeRunning {
                ShareLink(item: files.probeOutput) {
                    Label("Share image diagnostic", systemImage: "square.and.arrow.up")
                }
                .font(.footnote)
                .tint(.mint)
            }
        }
        .padding(14)
        .background(.white.opacity(0.07), in: RoundedRectangle(cornerRadius: 12))
    }

    var body: some View {
        GeometryReader { geometry in
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    HStack(spacing: 10) {
                        Image(systemName: "flag.checkered")
                            .font(.title2)
                            .foregroundStyle(.mint)
                        Text("NFSU2 / iOS")
                            .font(.system(.title, design: .monospaced, weight: .black))
                            .foregroundStyle(.white)
                    }

                    Text("APPLE SILICON · STAGE 5: NATIVE ENTRY PROBE")
                        .font(.system(.caption, design: .monospaced, weight: .semibold))
                        .tracking(1.1)
                        .foregroundStyle(.mint)

                    MetalPreview(previewTouchActive: $previewTouchActive)
                        .frame(height: max(190, min(geometry.size.height * 0.30, 320)))
                        .background(.black)
                        .clipShape(RoundedRectangle(cornerRadius: 16))
                        .overlay(alignment: .bottomLeading) {
                            Text("METAL DEVICE TEST · NOT GAMEPLAY")
                                .font(.system(size: 10, weight: .bold, design: .monospaced))
                                .padding(12)
                                .foregroundStyle(.white.opacity(0.85))
                        }

                    ActivePreviewInputPanel()

                    HStack(spacing: 8) {
                        Image(systemName: "checkmark.circle.fill")
                            .foregroundStyle(.mint)
                        Text("Native iOS Metal bootstrap preview")
                            .foregroundStyle(.white)
                    }
                    .font(.subheadline)

                    VStack(alignment: .leading, spacing: 10) {
                        Text("GUEST CPU + MEMORY SMOKE TEST")
                            .font(.system(.caption, design: .monospaced, weight: .bold))
                            .foregroundStyle(.mint)

                        Text("Tests the shared macOS/iOS guest memory and dispatcher core, CPU flags, stack operations, address limits and page permissions. It does not boot NFSU2.")
                            .font(.footnote)
                            .foregroundStyle(.white.opacity(0.7))

                        Button(action: startSmokeTest) {
                            Label(smokeRunning ? "Testing…" : "RUN CPU + MEMORY TEST",
                                  systemImage: "cpu")
                                .fontWeight(.bold)
                                .frame(maxWidth: .infinity)
                                .padding(10)
                        }
                        .buttonStyle(.borderedProminent)
                        .tint(.mint)
                        .disabled(smokeRunning || files.probeRunning)

                        HStack(alignment: .top, spacing: 8) {
                            Image(systemName: smokeRunning ? "hourglass" :
                                  (smokePassed ? "checkmark.circle.fill" : "info.circle"))
                            Text(smokeOutput)
                                .textSelection(.enabled)
                        }
                        .foregroundStyle(smokePassed ? .mint : .white)
                        .font(.system(.footnote, design: .monospaced))

                        if !smokeRunning {
                            ShareLink(item: smokeOutput) {
                                Label("Share test diagnostic", systemImage: "square.and.arrow.up")
                            }
                            .font(.footnote)
                            .tint(.mint)
                        }
                    }
                    .padding(14)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(.white.opacity(0.07), in: RoundedRectangle(cornerRadius: 12))

                    Text("In Files, choose your locally owned SPEED2.EXE. Its saved copy is authenticated before every native image probe.")
                        .font(.subheadline)
                        .foregroundStyle(.white.opacity(0.7))

                    Button {
                        activeFileImport = .executable
                    } label: {
                        Label("Select SPEED2.EXE", systemImage: "doc.badge.plus")
                            .fontWeight(.bold)
                            .frame(maxWidth: .infinity)
                            .padding(12)
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(.mint)
                    .disabled(smokeRunning || files.probeRunning || activeFileImport != nil)
                    .accessibilityIdentifier("select-game-executable")
                    .accessibilityHint("Opens Files so you can select the original SPEED2.EXE.")

                    VStack(alignment: .leading, spacing: 7) {
                        Text("GAME BUILD CHECK")
                            .font(.system(.caption, design: .monospaced, weight: .bold))
                            .foregroundStyle(.white.opacity(0.5))
                        Text(files.message)
                            .font(.system(.subheadline, design: .monospaced))
                            .foregroundStyle(files.isVerified ? .mint : .white)
                            .textSelection(.enabled)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(14)
                    .background(.white.opacity(0.065), in: RoundedRectangle(cornerRadius: 12))

                    imageProbePanel

                    Text("This app provides native runtime diagnostics. Full game boot, game rendering, audio and input integration are still pending.")
                        .font(.footnote)
                        .foregroundStyle(.white.opacity(0.6))
                }
                .padding(20)
                .frame(maxWidth: 800)
                .frame(maxWidth: .infinity)
            }
            .scrollDisabled(previewTouchActive || !inheritedScrollEnabled)
            .background(Color(red: 0.045, green: 0.07, blue: 0.095))
        }
        .preferredColorScheme(.dark)
        .gameFileImporter(selection: $activeFileImport) { request, outcome in
            guard request == .executable else { return }
            switch outcome {
            case .selected(let url):
                files.importExecutable(from: url)
            case .cancelled:
                break
            case .failed(let error):
                files.message = "File selection failed: \(error.localizedDescription)"
            }
        }
    }
}
#endif
