import MetalKit
import SwiftUI
import UIKit
import Combine

/// This is a real, native Metal render-pass sanity test — NOT NFSU2 gameplay.
struct MetalPreview: UIViewRepresentable {
    @Binding private var previewTouchActive: Bool

    init(previewTouchActive: Binding<Bool> = .constant(false)) {
        self._previewTouchActive = previewTouchActive
    }

    func makeCoordinator() -> PreviewRenderer {
        PreviewRenderer(previewTouchActive: $previewTouchActive)
    }

    func makeUIView(context: Context) -> MTKView {
        let view = InputPreviewMTKView(frame: .zero, device: context.coordinator.device)
        view.colorPixelFormat = .bgra8Unorm
        view.clearColor = MTLClearColor(red: 0.03, green: 0.09, blue: 0.13, alpha: 1)
        view.preferredFramesPerSecond = 60
        view.isPaused = false
        view.enableSetNeedsDisplay = false
        view.delegate = context.coordinator
        view.inputHandler = context.coordinator
        context.coordinator.attach(to: view)
        return view
    }

    func updateUIView(_ uiView: MTKView, context: Context) {
        if let inputView = uiView as? InputPreviewMTKView {
            context.coordinator.updateViewport(for: inputView)
        }
    }

    static func dismantleUIView(_ uiView: MTKView, coordinator: PreviewRenderer) {
        guard let inputView = uiView as? InputPreviewMTKView else { return }
        coordinator.detach(from: inputView)
    }
}

final class InputPreviewMTKView: MTKView {
    weak var inputHandler: PreviewRenderer?

    override func layoutSubviews() {
        super.layoutSubviews()
        inputHandler?.updateViewport(for: self)
        inputHandler?.viewAttached(to: self)
    }

    override func didMoveToWindow() {
        super.didMoveToWindow()
        if window == nil {
            inputHandler?.viewDetached()
        } else {
            inputHandler?.viewAttached(to: self)
        }
    }

    override func touchesBegan(_ touches: Set<UITouch>, with event: UIEvent?) {
        super.touchesBegan(touches, with: event)
        inputHandler?.touchesBegan(touches, in: self)
    }

    override func touchesMoved(_ touches: Set<UITouch>, with event: UIEvent?) {
        super.touchesMoved(touches, with: event)
        inputHandler?.touchesMoved(touches, in: self)
    }

    override func touchesEnded(_ touches: Set<UITouch>, with event: UIEvent?) {
        super.touchesEnded(touches, with: event)
        inputHandler?.touchesEnded(touches, in: self)
    }

    override func touchesCancelled(_ touches: Set<UITouch>, with event: UIEvent?) {
        super.touchesCancelled(touches, with: event)
        inputHandler?.touchesCancelled(touches, in: self)
    }
}

final class PreviewRenderer: NSObject, MTKViewDelegate {
    let device: MTLDevice?
    private let queue: MTLCommandQueue?
    private let pipeline: MTLRenderPipelineState?
    private let previewTouchActive: Binding<Bool>
    private var activeTouches: [ObjectIdentifier: UITouch] = [:]
    private var primaryTouchID: ObjectIdentifier?
    private var hoverPoint: CGPoint?
    private var isHovering = false
    private var hoverRecognizer: UIHoverGestureRecognizer?
    private var backgroundObserver: NSObjectProtocol?
    private var foregroundObserver: NSObjectProtocol?
    private weak var inputView: InputPreviewMTKView?
    private weak var ancestorScrollView: UIScrollView?
    private var savedDelaysContentTouches: Bool?

    init(previewTouchActive: Binding<Bool>) {
        self.previewTouchActive = previewTouchActive
        let gpu = MTLCreateSystemDefaultDevice()
        device = gpu
        queue = gpu?.makeCommandQueue()
        if let gpu = gpu,
           let library = gpu.makeDefaultLibrary(),
           let vertex = library.makeFunction(name: "bootVertex"),
           let fragment = library.makeFunction(name: "bootFragment") {
            let desc = MTLRenderPipelineDescriptor()
            desc.vertexFunction = vertex
            desc.fragmentFunction = fragment
            desc.colorAttachments[0].pixelFormat = .bgra8Unorm
            pipeline = try? gpu.makeRenderPipelineState(descriptor: desc)
        } else {
            pipeline = nil
        }
        super.init()
    }

    deinit {
        if let backgroundObserver {
            NotificationCenter.default.removeObserver(backgroundObserver)
        }
        if let foregroundObserver {
            NotificationCenter.default.removeObserver(foregroundObserver)
        }
    }

    func attach(to view: InputPreviewMTKView) {
        inputView = view
        view.isMultipleTouchEnabled = true
        updateViewport(for: view)
        viewAttached(to: view)
        nfsu2_input_set_cursor_available(false)
        previewTouchActive.wrappedValue = false

        let hover = UIHoverGestureRecognizer(target: self, action: #selector(handleHover(_:)))
        view.addGestureRecognizer(hover)
        hoverRecognizer = hover

        backgroundObserver = NotificationCenter.default.addObserver(
            forName: UIApplication.willResignActiveNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            self?.clearInput()
            self?.restoreScrollTouchDelay()
        }
        foregroundObserver = NotificationCenter.default.addObserver(
            forName: UIApplication.didBecomeActiveNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            guard let self, let inputView = self.inputView else { return }
            self.viewAttached(to: inputView)
        }
    }

    func detach(from view: InputPreviewMTKView) {
        clearInput()
        restoreScrollTouchDelay()
        inputView = nil
        if let hoverRecognizer {
            view.removeGestureRecognizer(hoverRecognizer)
            self.hoverRecognizer = nil
        }
        view.inputHandler = nil
    }

    func viewDetached() {
        clearInput()
        restoreScrollTouchDelay()
        inputView = nil
    }

    func viewAttached(to view: InputPreviewMTKView) {
        inputView = view
        var ancestor = view.superview
        while let candidate = ancestor, !(candidate is UIScrollView) {
            ancestor = candidate.superview
        }
        guard let scrollView = ancestor as? UIScrollView,
              scrollView !== ancestorScrollView else { return }

        restoreScrollTouchDelay()
        ancestorScrollView = scrollView
        savedDelaysContentTouches = scrollView.delaysContentTouches
        scrollView.delaysContentTouches = false
    }

    private func restoreScrollTouchDelay() {
        if let savedDelaysContentTouches,
           let ancestorScrollView {
            ancestorScrollView.delaysContentTouches = savedDelaysContentTouches
        }
        savedDelaysContentTouches = nil
        ancestorScrollView = nil
    }

    func updateViewport(for view: UIView) {
        let width = view.bounds.width > 0 ? view.bounds.width.rounded(.up) : 1280
        let height = view.bounds.height > 0 ? view.bounds.height.rounded(.up) : 720
        let viewportWidth = UInt32(min(width, CGFloat(UInt32.max)))
        let viewportHeight = UInt32(min(height, CGFloat(UInt32.max)))
        nfsu2_input_set_viewport(max(viewportWidth, 1), max(viewportHeight, 1), 1280, 720)
    }

    func touchesBegan(_ touches: Set<UITouch>, in view: UIView) {
        for touch in touches {
            activeTouches[ObjectIdentifier(touch)] = touch
        }
        if !touches.isEmpty {
            previewTouchActive.wrappedValue = true
        }
        guard primaryTouchID == nil,
              let first = touches.min(by: { $0.timestamp < $1.timestamp }) else { return }
        primaryTouchID = ObjectIdentifier(first)
        publish(first, in: view)
    }

    func touchesMoved(_ touches: Set<UITouch>, in view: UIView) {
        guard let primaryTouchID,
              let primary = activeTouches[primaryTouchID],
              touches.contains(where: { $0 === primary }) else { return }
        publish(primary, in: view)
    }

    func touchesEnded(_ touches: Set<UITouch>, in view: UIView) {
        let endingIDs = Set(touches.map { ObjectIdentifier($0) })
        for id in endingIDs {
            activeTouches.removeValue(forKey: id)
        }
        if activeTouches.isEmpty {
            previewTouchActive.wrappedValue = false
        }
        guard let primaryTouchID, endingIDs.contains(primaryTouchID) else { return }

        if let next = activeTouches.values.min(by: { $0.timestamp < $1.timestamp }) {
            self.primaryTouchID = ObjectIdentifier(next)
            publish(next, in: view)
        } else {
            self.primaryTouchID = nil
            publishHoverOrUnavailable()
        }
    }

    func touchesCancelled(_ touches: Set<UITouch>, in view: UIView) {
        clearInput()
    }

    private func publish(_ touch: UITouch, in view: UIView) {
        let point = touch.location(in: view)
        nfsu2_input_set_cursor(Float(point.x), Float(point.y), true)
    }

    @objc private func handleHover(_ recognizer: UIHoverGestureRecognizer) {
        switch recognizer.state {
        case .began, .changed:
            isHovering = true
            hoverPoint = recognizer.location(in: recognizer.view)
            if primaryTouchID == nil {
                publishHoverOrUnavailable()
            }
        case .ended, .cancelled, .failed:
            isHovering = false
            hoverPoint = nil
            if primaryTouchID == nil {
                nfsu2_input_set_cursor_available(false)
            }
        default:
            break
        }
    }

    private func publishHoverOrUnavailable() {
        guard isHovering, let hoverPoint else {
            nfsu2_input_set_cursor_available(false)
            return
        }
        nfsu2_input_set_cursor(Float(hoverPoint.x), Float(hoverPoint.y), false)
    }

    private func clearInput() {
        activeTouches.removeAll()
        primaryTouchID = nil
        isHovering = false
        hoverPoint = nil
        previewTouchActive.wrappedValue = false
        nfsu2_input_set_cursor_available(false)
    }

    func mtkView(_ view: MTKView, drawableSizeWillChange size: CGSize) {
        updateViewport(for: view)
    }

    func draw(in view: MTKView) {
        guard let queue = queue,
              let pipeline = pipeline,
              let pass = view.currentRenderPassDescriptor,
              let drawable = view.currentDrawable,
              let buffer = queue.makeCommandBuffer(),
              let encoder = buffer.makeRenderCommandEncoder(descriptor: pass)
        else { return }
        encoder.setRenderPipelineState(pipeline)
        encoder.drawPrimitives(type: .triangle, vertexStart: 0, vertexCount: 3)
        encoder.endEncoding()
        buffer.present(drawable)
        buffer.commit()
    }
}

/// Periodically reads the active native input bridge for diagnostics only.
struct ActivePreviewInputPanel: View {
    @State private var cursorStatus = "unavailable"
    private let refresh = Timer.publish(every: 0.1, on: .main, in: .common).autoconnect()

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("LIVE PREVIEW POINTER · NATIVE DIAGNOSTIC")
                .font(.system(.caption, design: .monospaced, weight: .bold))
                .foregroundStyle(.mint)
            Text(cursorStatus)
                .font(.system(.footnote, design: .monospaced, weight: .semibold))
                .foregroundStyle(.white)
                .accessibilityIdentifier("liveNativeCursorStatus")
            Text("Touch and hover readback only · not gameplay")
                .font(.footnote)
                .foregroundStyle(.white.opacity(0.65))
            Text("DETERMINISTIC ENTRY PROFILE · synthetic (320, 180) · harness fixture")
                .font(.system(size: 10, weight: .medium, design: .monospaced))
                .foregroundStyle(.white.opacity(0.55))
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(12)
        .background(.white.opacity(0.07), in: RoundedRectangle(cornerRadius: 12))
        .onAppear(perform: refreshCursor)
        .onReceive(refresh) { _ in refreshCursor() }
    }

    private func refreshCursor() {
        var x: Int32 = 0
        var y: Int32 = 0
        var flags: UInt32 = 0
        guard nfsu2_input_get_cursor_snapshot(&x, &y, &flags) else {
            cursorStatus = "native cursor unavailable"
            return
        }
        let down = (flags & UInt32(NFSU2_INPUT_CURSOR_FLAG_DOWN)) != 0
        cursorStatus = "native x: \(x)  y: \(y)  down: \(down ? "yes" : "no")"
    }
}
