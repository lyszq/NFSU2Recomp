import MetalKit
import SwiftUI

/// This is a real, native Metal render-pass sanity test — NOT NFSU2 gameplay.
struct MetalPreview: UIViewRepresentable {
    func makeCoordinator() -> PreviewRenderer {
        PreviewRenderer()
    }

    func makeUIView(context: Context) -> MTKView {
        let view = MTKView(frame: .zero, device: context.coordinator.device)
        view.colorPixelFormat = .bgra8Unorm
        view.clearColor = MTLClearColor(red: 0.03, green: 0.09, blue: 0.13, alpha: 1)
        view.preferredFramesPerSecond = 60
        view.isPaused = false
        view.enableSetNeedsDisplay = false
        view.delegate = context.coordinator
        return view
    }

    func updateUIView(_ uiView: MTKView, context: Context) {}
}

final class PreviewRenderer: NSObject, MTKViewDelegate {
    let device: MTLDevice?
    private let queue: MTLCommandQueue?
    private let pipeline: MTLRenderPipelineState?

    override init() {
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

    func mtkView(_ view: MTKView, drawableSizeWillChange size: CGSize) {}

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
