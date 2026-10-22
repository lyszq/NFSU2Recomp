import SwiftUI
import UIKit
import UniformTypeIdentifiers

enum GameFileSelectionRequest: String, Identifiable {
    case executable
    case gameFolder

    var id: String { rawValue }

    var allowedContentTypes: [UTType] {
        switch self {
        case .executable:
            // Files can report SPEED2.EXE as a generic item. The importer
            // validates the selected name and contents after the user picks it.
            return [.item]
        case .gameFolder:
            return [.folder]
        }
    }
}

enum GameFileSelectionOutcome {
    case selected(URL)
    case cancelled
    case failed(Error)
}

private struct GameFileImporterModifier: ViewModifier {
    @Binding var request: GameFileSelectionRequest?
    let onCompletion: (GameFileSelectionRequest, GameFileSelectionOutcome) -> Void

    func body(content: Content) -> some View {
        content
            .sheet(item: $request) { presentedRequest in
                GameDocumentPicker(request: presentedRequest) { outcome in
                    request = nil
                    onCompletion(presentedRequest, outcome)
                }
            }
    }
}

private struct GameDocumentPicker: UIViewControllerRepresentable {
    let request: GameFileSelectionRequest
    let onCompletion: (GameFileSelectionOutcome) -> Void

    func makeCoordinator() -> Coordinator { Coordinator(onCompletion: onCompletion) }

    func makeUIViewController(context: Context) -> UIDocumentPickerViewController {
        let picker = UIDocumentPickerViewController(
            forOpeningContentTypes: request.allowedContentTypes, asCopy: false)
        picker.allowsMultipleSelection = false
        picker.delegate = context.coordinator
        return picker
    }

    func updateUIViewController(_ controller: UIDocumentPickerViewController, context: Context) {}

    final class Coordinator: NSObject, UIDocumentPickerDelegate {
        private let onCompletion: (GameFileSelectionOutcome) -> Void
        private var completed = false

        init(onCompletion: @escaping (GameFileSelectionOutcome) -> Void) {
            self.onCompletion = onCompletion
        }

        private func finish(_ outcome: GameFileSelectionOutcome) {
            guard !completed else { return }
            completed = true
            onCompletion(outcome)
        }

        func documentPicker(_ controller: UIDocumentPickerViewController,
                            didPickDocumentsAt urls: [URL]) {
            // GameFileState keeps security-scoped access for the whole copy.
            if let url = urls.first { finish(.selected(url)) }
            else { finish(.cancelled) }
        }

        func documentPickerWasCancelled(_ controller: UIDocumentPickerViewController) {
            finish(.cancelled)
        }
    }
}

extension View {
    func gameFileImporter(
        selection: Binding<GameFileSelectionRequest?>,
        onCompletion: @escaping (GameFileSelectionRequest, GameFileSelectionOutcome) -> Void
    ) -> some View {
        modifier(GameFileImporterModifier(request: selection, onCompletion: onCompletion))
    }
}
