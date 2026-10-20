import SwiftUI
import MetalKit
import GameController

// MARK: - GameController Yöneticisi (DualSense, Xbox, MFi)

public final class GameControllerManager: ObservableObject {
    public static let shared = GameControllerManager()
    
    @Published public private(set) var connectedControllerName: String? = nil
    @Published public private(set) var isControllerConnected: Bool = false
    
    private init() {
        setupObservers()
        checkForExistingControllers()
    }
    
    private func setupObservers() {
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(controllerDidConnect(_:)),
            name: .GCControllerDidConnect,
            object: nil
        )
        
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(controllerDidDisconnect(_:)),
            name: .GCControllerDidDisconnect,
            object: nil
        )
    }
    
    @objc private func controllerDidConnect(_ notification: Notification) {
        if let controller = notification.object as? GCController {
            configureController(controller)
        }
    }
    
    @objc private func controllerDidDisconnect(_ notification: Notification) {
        checkForExistingControllers()
    }
    
    private func checkForExistingControllers() {
        if let controller = GCController.controllers().first {
            configureController(controller)
        } else {
            DispatchQueue.main.async {
                self.connectedControllerName = nil
                self.isControllerConnected = false
            }
            nfsu2_input_clear_all()
        }
    }
    
    public func configureController(_ controller: GCController) {
        DispatchQueue.main.async {
            self.connectedControllerName = controller.vendorName ?? "Oyun Kolu"
            self.isControllerConnected = true
        }
        
        // 1. Extended Gamepad (DualSense, DualShock 4, Xbox Series/One, Switch Pro, MFi)
        if let extended = controller.extendedGamepad {
            setupExtendedGamepad(extended)
        } else if let micro = controller.microGamepad {
            setupMicroGamepad(micro)
        }
    }
    
    private func setupExtendedGamepad(_ gamepad: GCExtendedGamepad) {
        // --- Gaz (R2 / RT Tetik) & Fren (L2 / LT Tetik) ---
        gamepad.rightTrigger.valueChangedHandler = { _, value, _ in
            nfsu2_input_set_throttle(value)
        }
        
        gamepad.leftTrigger.valueChangedHandler = { _, value, _ in
            nfsu2_input_set_brake(value)
        }
        
        // --- Direksiyon (Sol Analog Çubuk & D-Pad) ---
        gamepad.leftThumbstick.xAxis.valueChangedHandler = { _, x in
            nfsu2_input_set_steering(x)
        }
        
        gamepad.dpad.left.pressedChangedHandler = { _, _, pressed in
            nfsu2_input_set_key(UInt8(NFSU2_DIK_LEFT), pressed)
            nfsu2_input_set_key(UInt8(NFSU2_DIK_A), pressed)
        }
        
        gamepad.dpad.right.pressedChangedHandler = { _, _, pressed in
            nfsu2_input_set_key(UInt8(NFSU2_DIK_RIGHT), pressed)
            nfsu2_input_set_key(UInt8(NFSU2_DIK_D), pressed)
        }
        
        gamepad.dpad.up.pressedChangedHandler = { _, _, pressed in
            nfsu2_input_set_key(UInt8(NFSU2_DIK_UP), pressed)
            nfsu2_input_set_key(UInt8(NFSU2_DIK_W), pressed)
        }
        
        gamepad.dpad.down.pressedChangedHandler = { _, _, pressed in
            nfsu2_input_set_key(UInt8(NFSU2_DIK_DOWN), pressed)
            nfsu2_input_set_key(UInt8(NFSU2_DIK_S), pressed)
        }
        
        // --- El Freni (B / Daire & L1 / LB) ---
        gamepad.buttonB.pressedChangedHandler = { _, _, pressed in
            nfsu2_input_set_key(UInt8(NFSU2_DIK_SPACE), pressed)
        }
        
        gamepad.leftShoulder.pressedChangedHandler = { _, _, pressed in
            nfsu2_input_set_key(UInt8(NFSU2_DIK_SPACE), pressed)
        }
        
        // --- NOS / Nitro (X / Kare & R1 / RB) ---
        gamepad.buttonX.pressedChangedHandler = { _, _, pressed in
            nfsu2_input_set_key(UInt8(NFSU2_DIK_LSHIFT), pressed)
            nfsu2_input_set_key(UInt8(NFSU2_DIK_N), pressed)
        }
        
        gamepad.rightShoulder.pressedChangedHandler = { _, _, pressed in
            nfsu2_input_set_key(UInt8(NFSU2_DIK_LSHIFT), pressed)
            nfsu2_input_set_key(UInt8(NFSU2_DIK_N), pressed)
        }
        
        // --- Menü / Seç (A / Çarpı) ---
        gamepad.buttonA.pressedChangedHandler = { _, _, pressed in
            nfsu2_input_set_key(UInt8(NFSU2_DIK_RETURN), pressed)
        }
        
        // --- Kamera Görünümü (Y / Üçgen) ---
        gamepad.buttonY.pressedChangedHandler = { _, _, pressed in
            nfsu2_input_set_key(UInt8(NFSU2_DIK_C), pressed)
        }
        
        // --- Menü / Duraklat (Start / Options / Menu) ---
        gamepad.buttonMenu.pressedChangedHandler = { _, _, pressed in
            nfsu2_input_set_key(UInt8(NFSU2_DIK_ESCAPE), pressed)
        }
        
        gamepad.buttonOptions?.pressedChangedHandler = { _, _, pressed in
            nfsu2_input_set_key(UInt8(NFSU2_DIK_ESCAPE), pressed)
        }
        
        // --- Aracı Sıfırla (L3 / Sol Çubuk Tıklama) ---
        gamepad.leftThumbstickButton?.pressedChangedHandler = { _, _, pressed in
            nfsu2_input_set_key(UInt8(NFSU2_DIK_R), pressed)
        }
        
        // --- Arkaya Bak (R3 / Sağ Çubuk Tıklama) ---
        gamepad.rightThumbstickButton?.pressedChangedHandler = { _, _, pressed in
            nfsu2_input_set_key(UInt8(NFSU2_DIK_B), pressed)
        }
    }
    
    private func setupMicroGamepad(_ gamepad: GCMicroGamepad) {
        gamepad.dpad.xAxis.valueChangedHandler = { _, x in
            nfsu2_input_set_steering(x)
        }
        gamepad.buttonA.pressedChangedHandler = { _, _, pressed in
            nfsu2_input_set_key(UInt8(NFSU2_DIK_UP), pressed)
        }
        gamepad.buttonX.pressedChangedHandler = { _, _, pressed in
            nfsu2_input_set_key(UInt8(NFSU2_DIK_DOWN), pressed)
        }
        gamepad.buttonMenu.pressedChangedHandler = { _, _, pressed in
            nfsu2_input_set_key(UInt8(NFSU2_DIK_ESCAPE), pressed)
        }
    }
}

// MARK: - Dokunmatik Kontrol Düğmesi (Multi-Touch Uyumlu)

public struct TouchControlButton: View {
    let icon: String
    let label: String
    let dikCode: UInt8
    let secondaryDik: UInt8?
    let tintColor: Color
    let size: CGSize
    
    @State private var isPressed: Bool = false
    
    public init(
        icon: String,
        label: String,
        dikCode: UInt8,
        secondaryDik: UInt8? = nil,
        tintColor: Color = .mint,
        size: CGSize = CGSize(width: 72, height: 72)
    ) {
        self.icon = icon
        self.label = label
        self.dikCode = dikCode
        self.secondaryDik = secondaryDik
        self.tintColor = tintColor
        self.size = size
    }
    
    public var body: some View {
        ZStack {
            RoundedRectangle(cornerRadius: 18)
                .fill(tintColor.opacity(isPressed ? 0.60 : 0.22))
                .background(
                    RoundedRectangle(cornerRadius: 18)
                        .fill(Color.black.opacity(0.35))
                )
                .overlay(
                    RoundedRectangle(cornerRadius: 18)
                        .stroke(tintColor.opacity(isPressed ? 1.0 : 0.45), lineWidth: 2)
                )
                .shadow(color: isPressed ? tintColor.opacity(0.7) : .clear, radius: 8)
            
            VStack(spacing: 3) {
                Image(systemName: icon)
                    .font(.system(size: size.width * 0.32, weight: .bold))
                if !label.isEmpty {
                    Text(label)
                        .font(.system(size: 10, weight: .heavy, design: .monospaced))
                }
            }
            .foregroundStyle(.white)
        }
        .frame(width: size.width, height: size.height)
        .scaleEffect(isPressed ? 0.93 : 1.0)
        .animation(.easeOut(duration: 0.08), value: isPressed)
        .gesture(
            DragGesture(minimumDistance: 0)
                .onChanged { _ in
                    if !isPressed {
                        isPressed = true
                        nfsu2_input_set_key(dikCode, true)
                        if let sec = secondaryDik {
                            nfsu2_input_set_key(sec, true)
                        }
                        UIImpactFeedbackGenerator(style: .light).impactOccurred()
                    }
                }
                .onEnded { _ in
                    isPressed = false
                    nfsu2_input_set_key(dikCode, false)
                    if let sec = secondaryDik {
                        nfsu2_input_set_key(sec, false)
                    }
                }
        )
    }
}

// MARK: - Dokunmatik Kontroller Arayüzü (HUD Katmanı)

public struct OnScreenControlsOverlay: View {
    @ObservedObject var controllerManager = GameControllerManager.shared
    @Binding var showControls: Bool
    
    public init(showControls: Binding<Bool> = .constant(true)) {
        self._showControls = showControls
    }
    
    public var body: some View {
        ZStack {
            // Kontrolcü bağlı ise üstte bildirim çubuğu
            VStack {
                HStack {
                    // Kamera Değiştir
                    TouchControlButton(
                        icon: "camera.viewfinder",
                        label: "KAMERA",
                        dikCode: UInt8(NFSU2_DIK_C),
                        tintColor: .cyan,
                        size: CGSize(width: 58, height: 42)
                    )
                    
                    // Aracı Sıfırla
                    TouchControlButton(
                        icon: "arrow.counterclockwise.circle",
                        label: "SIFIRLA",
                        dikCode: UInt8(NFSU2_DIK_R),
                        tintColor: .orange,
                        size: CGSize(width: 58, height: 42)
                    )
                    
                    Spacer()
                    
                    if let controllerName = controllerManager.connectedControllerName {
                        HStack(spacing: 6) {
                            Image(systemName: "gamecontroller.fill")
                                .foregroundStyle(.mint)
                            Text(controllerName)
                                .font(.system(size: 11, weight: .semibold, design: .monospaced))
                                .foregroundStyle(.white)
                        }
                        .padding(.horizontal, 10)
                        .padding(.vertical, 5)
                        .background(.ultraThinMaterial, in: Capsule())
                        
                        Spacer()
                    }
                    
                    // Duraklat / Menü (ESC)
                    TouchControlButton(
                        icon: "pause.fill",
                        label: "ESC",
                        dikCode: UInt8(NFSU2_DIK_ESCAPE),
                        tintColor: .yellow,
                        size: CGSize(width: 58, height: 42)
                    )
                }
                .padding(.horizontal, 16)
                .padding(.top, 10)
                
                Spacer()
                
                if showControls {
                    // Alt Bölüm: Direksiyon (Sol) & Pedallar/Nitro (Sağ)
                    HStack(alignment: .bottom) {
                        // SOL BÖLGE: Direksiyon (Sol / Sağ)
                        HStack(spacing: 12) {
                            TouchControlButton(
                                icon: "arrow.left",
                                label: "SOL",
                                dikCode: UInt8(NFSU2_DIK_LEFT),
                                secondaryDik: UInt8(NFSU2_DIK_A),
                                tintColor: .blue,
                                size: CGSize(width: 76, height: 74)
                            )
                            
                            TouchControlButton(
                                icon: "arrow.right",
                                label: "SAĞ",
                                dikCode: UInt8(NFSU2_DIK_RIGHT),
                                secondaryDik: UInt8(NFSU2_DIK_D),
                                tintColor: .blue,
                                size: CGSize(width: 76, height: 74)
                            )
                        }
                        .padding(.leading, 16)
                        .padding(.bottom, 16)
                        
                        Spacer()
                        
                        // SAĞ BÖLGE: Fren, Gaz, El Freni, NOS
                        HStack(alignment: .bottom, spacing: 14) {
                            // İkincil Eylemler Sütunu: NOS & El Freni
                            VStack(spacing: 12) {
                                TouchControlButton(
                                    icon: "flame.fill",
                                    label: "NOS",
                                    dikCode: UInt8(NFSU2_DIK_LSHIFT),
                                    secondaryDik: UInt8(NFSU2_DIK_N),
                                    tintColor: .purple,
                                    size: CGSize(width: 66, height: 58)
                                )
                                
                                TouchControlButton(
                                    icon: "p.circle.fill",
                                    label: "E.FREN",
                                    dikCode: UInt8(NFSU2_DIK_SPACE),
                                    tintColor: .orange,
                                    size: CGSize(width: 66, height: 58)
                                )
                            }
                            
                            // Ana Pedallar: Fren & Gaz
                            HStack(spacing: 12) {
                                TouchControlButton(
                                    icon: "arrow.down.to.line.compact",
                                    label: "FREN",
                                    dikCode: UInt8(NFSU2_DIK_DOWN),
                                    secondaryDik: UInt8(NFSU2_DIK_S),
                                    tintColor: .red,
                                    size: CGSize(width: 72, height: 86)
                                )
                                
                                TouchControlButton(
                                    icon: "arrow.up.to.line.compact",
                                    label: "GAZ",
                                    dikCode: UInt8(NFSU2_DIK_UP),
                                    secondaryDik: UInt8(NFSU2_DIK_W),
                                    tintColor: .mint,
                                    size: CGSize(width: 76, height: 104)
                                )
                            }
                        }
                        .padding(.trailing, 16)
                        .padding(.bottom, 16)
                    }
                }
            }
        }
    }
}

// MARK: - GameMetalView (Metal Renderer + Dokunmatik Kontroller + GameController Entegrasyonu)

public struct GameMetalView: View {
    @StateObject private var controllerManager = GameControllerManager.shared
    @State private var showTouchOverlay: Bool = true
    
    public init() {}
    
    public var body: some View {
        ZStack {
            // Arka plandaki Metal Görünümü (60 FPS Metal render yüzeyi)
            MetalPreview()
                .ignoresSafeArea()
            
            // Üstteki Etkileşimli Kontrol Katmanı
            OnScreenControlsOverlay(showControls: $showTouchOverlay)
        }
        .onAppear {
            // Görünüm açıldığında bağlı kontrolcü varsa yapılandır
            if let activeController = GCController.current ?? GCController.controllers().first {
                controllerManager.configureController(activeController)
            }
        }
        .onDisappear {
            // Görünüm kapandığında tuşları serbest bırak
            nfsu2_input_clear_all()
        }
    }
}
