import SwiftUI

@main
struct NFSU2iOSApp: App {
    @StateObject private var gameFiles = GameFileState()
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(gameFiles)
                .onAppear { gameFiles.refreshSharedImport() }
                .onChange(of: scenePhase) { phase in
                    if phase == .active { gameFiles.refreshSharedImport() }
                }
        }
    }
}
