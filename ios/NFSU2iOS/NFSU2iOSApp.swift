import SwiftUI

@main
struct NFSU2iOSApp: App {
    @StateObject private var gameFiles = GameFileState()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(gameFiles)
        }
    }
}
