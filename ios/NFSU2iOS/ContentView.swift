import SwiftUI
import UIKit
import UniformTypeIdentifiers

struct ContentView: View {
    @EnvironmentObject private var files: GameFileState
    @State private var chooseExecutable = false
    @State private var smokeRunning = false
    @State private var smokePassed = false
    @State private var smokeOutput = "Not run yet. Tap RUN CPU + MEMORY TEST."

    private func startSmokeTest() {
        guard !smokeRunning else { return }
        smokeRunning = true
        smokePassed = false
        smokeOutput = "Running native CPU and virtual-memory tests…"

        let version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "?"
        let device = "iOS \(version) | \(UIDevice.current.model) \(UIDevice.current.systemName) \(UIDevice.current.systemVersion)"
        // Reserving a large virtual address range is not work for the UI thread.
        DispatchQueue.global(qos: .userInitiated).async {
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

                    Text("APPLE SILICON · STAGE 3: SHARED MEMORY")
                        .font(.system(.caption, design: .monospaced, weight: .semibold))
                        .tracking(1.1)
                        .foregroundStyle(.mint)

                    MetalPreview()
                        .frame(height: max(190, min(geometry.size.height * 0.30, 320)))
                        .background(.black)
                        .clipShape(RoundedRectangle(cornerRadius: 16))
                        .overlay(alignment: .bottomLeading) {
                            Text("METAL DEVICE TEST · NOT GAMEPLAY")
                                .font(.system(size: 10, weight: .bold, design: .monospaced))
                                .padding(12)
                                .foregroundStyle(.white.opacity(0.85))
                        }

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

                        Text("Tests the shared macOS/iOS guest memory core, CPU flags, stack operations, address limits and page permissions. It does not boot NFSU2.")
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
                        .disabled(smokeRunning)

                        HStack(alignment: .top, spacing: 8) {
                            Image(systemName: smokeRunning ? "hourglass" :
                                  (smokePassed ? "checkmark.circle.fill" : "info.circle"))
                            Text(smokeOutput)
                                .textSelection(.enabled)
                        }
                        .foregroundStyle(smokePassed ? .mint : .white)
                        .font(.system(.footnote, design: .monospaced))

                        if !smokeRunning {
                            ShareLink(item: "NFSU2 iOS 0.3 (shared memory core)\n" + smokeOutput) {
                                Label("Share test diagnostic", systemImage: "square.and.arrow.up")
                            }
                            .font(.footnote)
                            .tint(.mint)
                        }
                    }
                    .padding(14)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(.white.opacity(0.07), in: RoundedRectangle(cornerRadius: 12))

                    Text("Select your locally owned SPEED2.EXE. The file is verified and saved for a later stage; it is not executed.")
                        .font(.subheadline)
                        .foregroundStyle(.white.opacity(0.7))

                    Button {
                        chooseExecutable = true
                    } label: {
                        Label("Select SPEED2.EXE", systemImage: "doc.badge.plus")
                            .fontWeight(.bold)
                            .frame(maxWidth: .infinity)
                            .padding(12)
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(.mint)

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

                    Text("NEXT: Generate lifted C from your own EXE privately, port the guest boot process, then connect the macOS D3D9-to-Metal implementation to iOS. This IPA includes the shared memory core, but no lifted game code or game assets.")
                        .font(.footnote)
                        .foregroundStyle(.white.opacity(0.6))
                }
                .padding(20)
                .frame(maxWidth: 800)
                .frame(maxWidth: .infinity)
            }
            .background(Color(red: 0.045, green: 0.07, blue: 0.095))
        }
        .preferredColorScheme(.dark)
        .fileImporter(isPresented: $chooseExecutable, allowedContentTypes: [.item]) { result in
            switch result {
            case .success(let url):
                files.importExecutable(from: url)
            case .failure(let error):
                files.message = "File selection failed: \(error.localizedDescription)"
            }
        }
    }
}
