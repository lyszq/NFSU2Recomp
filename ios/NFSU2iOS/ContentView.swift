import SwiftUI
import UniformTypeIdentifiers

struct ContentView: View {
    @EnvironmentObject private var files: GameFileState
    @State private var chooseExecutable = false

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

                    Text("APPLE SILICON · METAL BOOTSTRAP")
                        .font(.system(.caption, design: .monospaced, weight: .semibold))
                        .tracking(1.4)
                        .foregroundStyle(.mint)

                    MetalPreview()
                        .frame(height: max(220, min(geometry.size.height * 0.43, 420)))
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
                        Text("Native iOS app and Metal renderer are linked")
                            .foregroundStyle(.white)
                    }
                    .font(.subheadline)

                    Text("Choose SPEED2.EXE from a legally obtained PC installation. This bootstrap verifies the supported build; it does not run the game yet.")
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

                    Text("Next milestone: adapt the macOS recompilation runtime from Cocoa/AppKit to UIKit and connect its D3D9-to-Metal renderer. No copyrighted game data is included in this build.")
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
