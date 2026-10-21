import SwiftUI
import MetalKit
import GameController
import QuartzCore

// MARK: - GameController Yöneticisi (DualSense, Xbox, Switch Pro, MFi)

public final class GameControllerManager: ObservableObject {
    public static let shared = GameControllerManager()
    
    @Published public private(set) var connectedControllerName: String? = nil
    @Published public private(set) var isControllerConnected: Bool = false
    @Published public private(set) var batteryLevel: Float? = nil
    
    private init() {
        setupObservers()
        checkForExistingControllers()
    }
    
    private func setupObservers() {
        let center = NotificationCenter.default
        
        center.addObserver(
            self,
            selector: #selector(controllerDidConnect(_:)),
            name: .GCControllerDidConnect,
            object: nil
        )
        
        center.addObserver(
            self,
            selector: #selector(controllerDidDisconnect(_:)),
            name: .GCControllerDidDisconnect,
            object: nil
        )
        
        center.addObserver(
            self,
            selector: #selector(controllerDidBecomeCurrent(_:)),
            name: .GCControllerDidBecomeCurrent,
            object: nil
        )
        
        center.addObserver(
            self,
            selector: #selector(controllerDidStopBeingCurrent(_:)),
            name: .GCControllerDidStopBeingCurrent,
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
    
    @objc private func controllerDidBecomeCurrent(_ notification: Notification) {
        if let controller = notification.object as? GCController {
            configureController(controller)
        }
    }
    
    @objc private func controllerDidStopBeingCurrent(_ notification: Notification) {
        checkForExistingControllers()
    }
    
    public func checkForExistingControllers() {
        if let controller = GCController.current ?? GCController.controllers().first {
            configureController(controller)
        } else {
            DispatchQueue.main.async {
                self.connectedControllerName = nil
                self.isControllerConnected = false
                self.batteryLevel = nil
            }
            // Kontrolcü koptuğunda takılı kalan girdileri temizle
            nfsu2_input_clear_all()
        }
    }
    
    public func configureController(_ controller: GCController) {
        let vendor = controller.vendorName ?? "Kablosuz Oyun Kolu"
        let battery = controller.battery?.batteryLevel
        
        DispatchQueue.main.async {
            self.connectedControllerName = vendor
            self.isControllerConnected = true
            self.batteryLevel = battery
        }
        
        // 1. Extended Gamepad (Sony DualSense, DualShock 4, Xbox Series/One, Switch Pro, MFi)
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

// MARK: - Dokunsal Titreşim (Haptics) Yöneticisi

private final class HapticFeedbackEngine {
    static let shared = HapticFeedbackEngine()
    private let impactLight = UIImpactFeedbackGenerator(style: .light)
    private let impactRigid = UIImpactFeedbackGenerator(style: .rigid)
    
    private init() {
        impactLight.prepare()
        impactRigid.prepare()
    }
    
    func tapLight() {
        impactLight.impactOccurred()
    }
    
    func tapRigid() {
        impactRigid.impactOccurred()
    }
}

// MARK: - Çoklu Dokunma Uyumlu Aksiyon Düğmesi (Zero-Latency Multi-Touch Button)

public struct MultiTouchKeyButton: View {
    let icon: String
    let label: String
    let dikCode: UInt8
    let secondaryDik: UInt8?
    let tintColor: Color
    let size: CGSize
    
    @State private var isPressed: Bool = false
    @State private var pressStartTime: Double = 0.0
    
    public init(
        icon: String,
        label: String,
        dikCode: UInt8,
        secondaryDik: UInt8? = nil,
        tintColor: Color = .mint,
        size: CGSize = CGSize(width: 68, height: 68)
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
                .fill(tintColor.opacity(isPressed ? 0.65 : 0.22))
                .background(
                    RoundedRectangle(cornerRadius: 18)
                        .fill(Color.black.opacity(0.40))
                )
                .overlay(
                    RoundedRectangle(cornerRadius: 18)
                        .stroke(tintColor.opacity(isPressed ? 1.0 : 0.50), lineWidth: isPressed ? 2.5 : 1.5)
                )
                .shadow(color: isPressed ? tintColor.opacity(0.8) : .clear, radius: 10)
            
            VStack(spacing: 3) {
                Image(systemName: icon)
                    .font(.system(size: size.width * 0.32, weight: .bold))
                if !label.isEmpty {
                    Text(label)
                        .font(.system(size: max(9, size.width * 0.14), weight: .heavy, design: .monospaced))
                }
            }
            .foregroundStyle(.white)
        }
        .frame(width: size.width, height: size.height)
        .scaleEffect(isPressed ? 0.92 : 1.0)
        .animation(.easeOut(duration: 0.06), value: isPressed)
        .gesture(
            DragGesture(minimumDistance: 0, coordinateSpace: .local)
                .onChanged { _ in
                    if !isPressed {
                        isPressed = true
                        pressStartTime = CACurrentMediaTime()
                        nfsu2_input_set_key(dikCode, true)
                        if let sec = secondaryDik {
                            nfsu2_input_set_key(sec, true)
                        }
                        HapticFeedbackEngine.shared.tapLight()
                    }
                }
                .onEnded { _ in
                    isPressed = false
                    let elapsed = CACurrentMediaTime() - pressStartTime
                    let minHoldDuration: Double = 0.050 // 50ms (garantili 3-4 DirectInput polling karesi)
                    let code = dikCode
                    let sec = secondaryDik
                    
                    if elapsed < minHoldDuration {
                        DispatchQueue.main.asyncAfter(deadline: .now() + (minHoldDuration - elapsed)) {
                            if !isPressed {
                                nfsu2_input_set_key(code, false)
                                if let s = sec {
                                    nfsu2_input_set_key(s, false)
                                }
                            }
                        }
                    } else {
                        nfsu2_input_set_key(code, false)
                        if let s = sec {
                            nfsu2_input_set_key(s, false)
                        }
                    }
                }
        )
    }
}

// MARK: - Yarış Pedalı Bileşeni (Gaz ve Fren)

public struct RacingPedalView: View {
    let label: String
    let subLabel: String
    let dikCode: UInt8
    let secondaryDik: UInt8?
    let tintColor: Color
    let size: CGSize
    
    @State private var isPressed: Bool = false
    @State private var pressStartTime: Double = 0.0
    
    public init(
        label: String,
        subLabel: String,
        dikCode: UInt8,
        secondaryDik: UInt8? = nil,
        tintColor: Color = .mint,
        size: CGSize = CGSize(width: 76, height: 104)
    ) {
        self.label = label
        self.subLabel = subLabel
        self.dikCode = dikCode
        self.secondaryDik = secondaryDik
        self.tintColor = tintColor
        self.size = size
    }
    
    public var body: some View {
        ZStack {
            // Pedal Arka Planı
            RoundedRectangle(cornerRadius: 16)
                .fill(tintColor.opacity(isPressed ? 0.70 : 0.25))
                .background(
                    RoundedRectangle(cornerRadius: 16)
                        .fill(Color.black.opacity(0.50))
                )
                .overlay(
                    RoundedRectangle(cornerRadius: 16)
                        .stroke(tintColor.opacity(isPressed ? 1.0 : 0.55), lineWidth: isPressed ? 3 : 1.8)
                )
                .shadow(color: isPressed ? tintColor.opacity(0.85) : .clear, radius: 12)
            
            // Pedal Çizgileri / Izgara Görünümü
            VStack(spacing: 6) {
                ForEach(0..<4) { _ in
                    Capsule()
                        .fill(Color.white.opacity(isPressed ? 0.60 : 0.25))
                        .frame(width: size.width * 0.65, height: 3.5)
                }
                
                Spacer().frame(height: 4)
                
                Text(label)
                    .font(.system(size: 13, weight: .black, design: .monospaced))
                    .foregroundStyle(.white)
                
                if !subLabel.isEmpty {
                    Text(subLabel)
                        .font(.system(size: 9, weight: .bold, design: .monospaced))
                        .foregroundStyle(tintColor.opacity(0.9))
                }
            }
            .padding(.vertical, 8)
        }
        .frame(width: size.width, height: size.height)
        .scaleEffect(isPressed ? 0.94 : 1.0)
        .animation(.easeOut(duration: 0.05), value: isPressed)
        .gesture(
            DragGesture(minimumDistance: 0, coordinateSpace: .local)
                .onChanged { _ in
                    if !isPressed {
                        isPressed = true
                        pressStartTime = CACurrentMediaTime()
                        nfsu2_input_set_key(dikCode, true)
                        if let sec = secondaryDik {
                            nfsu2_input_set_key(sec, true)
                        }
                        HapticFeedbackEngine.shared.tapRigid()
                    }
                }
                .onEnded { _ in
                    isPressed = false
                    let elapsed = CACurrentMediaTime() - pressStartTime
                    let minHoldDuration: Double = 0.050 // 50ms
                    let code = dikCode
                    let sec = secondaryDik
                    
                    if elapsed < minHoldDuration {
                        DispatchQueue.main.asyncAfter(deadline: .now() + (minHoldDuration - elapsed)) {
                            if !isPressed {
                                nfsu2_input_set_key(code, false)
                                if let s = sec {
                                    nfsu2_input_set_key(s, false)
                                }
                            }
                        }
                    } else {
                        nfsu2_input_set_key(code, false)
                        if let s = sec {
                            nfsu2_input_set_key(s, false)
                        }
                    }
                }
        )
    }
}

// MARK: - Analog Direksiyon Kaydırıcısı (Steer Slider)

public struct AnalogSteerSlider: View {
    let width: CGFloat
    let height: CGFloat
    
    @State private var dragOffset: CGFloat = 0.0
    @State private var isDragging: Bool = false
    
    private var maxRange: CGFloat {
        return (width - height) / 2.0
    }
    
    public init(width: CGFloat = 180, height: CGFloat = 58) {
        self.width = width
        self.height = height
    }
    
    public var body: some View {
        let normalizedValue = maxRange > 0 ? (dragOffset / maxRange) : 0.0
        
        ZStack {
            // Kaydırıcı Rayı (Track)
            RoundedRectangle(cornerRadius: height / 2)
                .fill(Color.black.opacity(0.45))
                .overlay(
                    RoundedRectangle(cornerRadius: height / 2)
                        .stroke(
                            LinearGradient(
                                colors: [
                                    .cyan.opacity(normalizedValue < -0.1 ? 0.9 : 0.3),
                                    .white.opacity(0.3),
                                    .cyan.opacity(normalizedValue > 0.1 ? 0.9 : 0.3)
                                ],
                                startPoint: .leading,
                                endPoint: .trailing
                            ),
                            lineWidth: 2
                        )
                )
            
            // Merkez Noktası İşareti
            Rectangle()
                .fill(Color.white.opacity(0.40))
                .frame(width: 2, height: height * 0.45)
            
            // Sol ve Sağ Yön Göstergeleri
            HStack {
                Image(systemName: "chevron.left.2")
                    .font(.system(size: 13, weight: .bold))
                    .foregroundStyle(normalizedValue < -0.15 ? Color.cyan : Color.white.opacity(0.35))
                    .padding(.leading, 12)
                
                Spacer()
                
                Image(systemName: "chevron.right.2")
                    .font(.system(size: 13, weight: .bold))
                    .foregroundStyle(normalizedValue > 0.15 ? Color.cyan : Color.white.opacity(0.35))
                    .padding(.trailing, 12)
            }
            
            // Hareketli Direksiyon Topuzu (Thumb Knob)
            Circle()
                .fill(
                    LinearGradient(
                        colors: isDragging ? [.cyan, .blue] : [.white.opacity(0.9), .gray.opacity(0.7)],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    )
                )
                .frame(width: height - 8, height: height - 8)
                .overlay(
                    Circle()
                        .stroke(Color.white, lineWidth: 2)
                )
                .shadow(color: isDragging ? .cyan.opacity(0.8) : .clear, radius: 8)
                .offset(x: dragOffset)
        }
        .frame(width: width, height: height)
        .gesture(
            DragGesture(minimumDistance: 0, coordinateSpace: .local)
                .onChanged { gesture in
                    isDragging = true
                    let rawX = gesture.location.x - (width / 2.0)
                    let clampedX = min(max(rawX, -maxRange), maxRange)
                    dragOffset = clampedX
                    
                    let norm = Float(clampedX / maxRange)
                    nfsu2_input_set_steering(norm)
                }
                .onEnded { _ in
                    isDragging = false
                    // Yaylanarak merkeze dön (Spring Return to Center)
                    withAnimation(.spring(response: 0.18, dampingFraction: 0.70)) {
                        dragOffset = 0.0
                    }
                    nfsu2_input_set_steering(0.0)
                    HapticFeedbackEngine.shared.tapLight()
                }
        )
    }
}

// MARK: - Dokunmatik Kontroller Arayüzü (HUD Katmanı)

public struct OnScreenControlsOverlay: View {
    @ObservedObject var controllerManager = GameControllerManager.shared
    @Binding var showControls: Bool
    
    // Direksiyon Kontrol Modu: Analog Kaydırıcı veya Dijital Tuşlar
    @State private var useAnalogSlider: Bool = true
    
    // Manuel Vites Tuşları Görünürlüğü
    @State private var showManualGears: Bool = false
    
    public init(showControls: Binding<Bool>) {
        self._showControls = showControls
    }
    
    private var isPad: Bool {
        UIDevice.current.userInterfaceIdiom == .pad
    }
    
    public var body: some View {
        GeometryReader { geo in
            let hPad: CGFloat = isPad ? 36 : 18
            let bPad: CGFloat = isPad ? 32 : 14
            
            let steerWidth: CGFloat = isPad ? 210 : 160
            let steerHeight: CGFloat = isPad ? 62 : 52
            let dpadSize: CGSize = isPad ? CGSize(width: 80, height: 76) : CGSize(width: 66, height: 66)
            let gasSize: CGSize = isPad ? CGSize(width: 80, height: 114) : CGSize(width: 72, height: 98)
            let brakeSize: CGSize = isPad ? CGSize(width: 74, height: 94) : CGSize(width: 66, height: 82)
            let actionSize: CGSize = isPad ? CGSize(width: 72, height: 62) : CGSize(width: 62, height: 54)
            let topBtnSize: CGSize = isPad ? CGSize(width: 68, height: 44) : CGSize(width: 56, height: 40)
            
            VStack {
                // ÜST BÖLÜM: Kamera, Harita, Sıfırla, Kontrolcü Durumu, Menü
                HStack(spacing: isPad ? 12 : 8) {
                    // Kamera Görünümü (C)
                    MultiTouchKeyButton(
                        icon: "camera.viewfinder",
                        label: "KAMERA",
                        dikCode: UInt8(NFSU2_DIK_C),
                        tintColor: .cyan,
                        size: topBtnSize
                    )
                    
                    // Arkaya Bak (B)
                    MultiTouchKeyButton(
                        icon: "eye.fill",
                        label: "ARKA",
                        dikCode: UInt8(NFSU2_DIK_B),
                        tintColor: .teal,
                        size: topBtnSize
                    )
                    
                    // Aracı Sıfırla (R)
                    MultiTouchKeyButton(
                        icon: "arrow.counterclockwise.circle",
                        label: "SIFIRLA",
                        dikCode: UInt8(NFSU2_DIK_R),
                        tintColor: .orange,
                        size: topBtnSize
                    )
                    
                    Spacer()
                    
                    // Eşleşmiş Kontrolcü Bildirimi
                    if let controllerName = controllerManager.connectedControllerName {
                        HStack(spacing: 6) {
                            Image(systemName: "gamecontroller.fill")
                                .foregroundStyle(.mint)
                            Text(controllerName)
                                .font(.system(size: isPad ? 12 : 10, weight: .bold, design: .monospaced))
                                .foregroundStyle(.white)
                            
                            if let battery = controllerManager.batteryLevel {
                                Image(systemName: battery > 0.2 ? "battery.75" : "battery.25")
                                    .foregroundStyle(battery > 0.2 ? .mint : .red)
                                    .font(.system(size: 11))
                            }
                        }
                        .padding(.horizontal, 12)
                        .padding(.vertical, 6)
                        .background(.ultraThinMaterial, in: Capsule())
                        .overlay(Capsule().stroke(Color.mint.opacity(0.4), lineWidth: 1))
                        
                        Spacer()
                    }
                    
                    // Direksiyon Modu Değiştirici Pill
                    Button {
                        useAnalogSlider.toggle()
                        HapticFeedbackEngine.shared.tapLight()
                    } label: {
                        HStack(spacing: 4) {
                            Image(systemName: useAnalogSlider ? "steeringwheel" : "dpad")
                            Text(useAnalogSlider ? "SLIDER" : "D-PAD")
                                .font(.system(size: 9, weight: .black, design: .monospaced))
                        }
                        .padding(.horizontal, 8)
                        .padding(.vertical, 6)
                        .background(Color.white.opacity(0.12), in: Capsule())
                        .foregroundStyle(.white)
                    }
                    
                    // Dokunmatik Kontrolleri Göster / Gizle Manuel Anahtarı
                    Button {
                        withAnimation(.easeInOut(duration: 0.20)) {
                            showControls.toggle()
                        }
                        HapticFeedbackEngine.shared.tapLight()
                    } label: {
                        Image(systemName: showControls ? "hand.tap.fill" : "hand.tap")
                            .font(.system(size: 14, weight: .bold))
                            .padding(8)
                            .background(showControls ? Color.mint.opacity(0.3) : Color.white.opacity(0.15), in: Circle())
                            .foregroundStyle(showControls ? .mint : .white)
                    }
                    
                    // Duraklat / Menü (ESC)
                    MultiTouchKeyButton(
                        icon: "pause.fill",
                        label: "ESC",
                        dikCode: UInt8(NFSU2_DIK_ESCAPE),
                        tintColor: .yellow,
                        size: topBtnSize
                    )
                }
                .padding(.horizontal, hPad)
                .padding(.top, isPad ? 16 : 8)
                
                Spacer()
                
                // ALT BÖLÜM: Sol Direksiyon Kontrolleri & Sağ Pedallar / Nitro
                if showControls {
                    HStack(alignment: .bottom) {
                        // --- SOL BÖLGE: DİREKSİYON & VİTES ---
                        VStack(alignment: .leading, spacing: 10) {
                            // Manuel Vites Düğmeleri (Q: Vites-, E: Vites+)
                            if showManualGears {
                                HStack(spacing: 8) {
                                    MultiTouchKeyButton(
                                        icon: "arrow.down.square",
                                        label: "V-",
                                        dikCode: UInt8(NFSU2_DIK_Q),
                                        tintColor: .indigo,
                                        size: CGSize(width: 50, height: 42)
                                    )
                                    MultiTouchKeyButton(
                                        icon: "arrow.up.square",
                                        label: "V+",
                                        dikCode: UInt8(NFSU2_DIK_E),
                                        tintColor: .indigo,
                                        size: CGSize(width: 50, height: 42)
                                    )
                                }
                            }
                            
                            if useAnalogSlider {
                                // 1. Analog Direksiyon Kaydırıcısı (Steer Slider)
                                AnalogSteerSlider(width: steerWidth, height: steerHeight)
                            } else {
                                // 2. Dijital D-Pad Tuşları (Sol / Sağ)
                                HStack(spacing: isPad ? 14 : 10) {
                                    MultiTouchKeyButton(
                                        icon: "arrow.left",
                                        label: "SOL",
                                        dikCode: UInt8(NFSU2_DIK_LEFT),
                                        secondaryDik: UInt8(NFSU2_DIK_A),
                                        tintColor: .blue,
                                        size: dpadSize
                                    )
                                    
                                    MultiTouchKeyButton(
                                        icon: "arrow.right",
                                        label: "SAĞ",
                                        dikCode: UInt8(NFSU2_DIK_RIGHT),
                                        secondaryDik: UInt8(NFSU2_DIK_D),
                                        tintColor: .blue,
                                        size: dpadSize
                                    )
                                }
                            }
                        }
                        .padding(.leading, hPad)
                        .padding(.bottom, bPad)
                        
                        Spacer()
                        
                        // --- SAĞ BÖLGE: PEDALLAR, EL FRENİ VE NOS ---
                        HStack(alignment: .bottom, spacing: isPad ? 16 : 12) {
                            // İkincil Eylemler Sütunu: NOS (Shift) & El Freni (Space)
                            VStack(spacing: isPad ? 12 : 9) {
                                // NOS / Nitro (Sol Shift / N)
                                MultiTouchKeyButton(
                                    icon: "flame.fill",
                                    label: "NOS",
                                    dikCode: UInt8(NFSU2_DIK_LSHIFT),
                                    secondaryDik: UInt8(NFSU2_DIK_N),
                                    tintColor: .purple,
                                    size: actionSize
                                )
                                
                                // El Freni / Drift (Boşluk / Space)
                                MultiTouchKeyButton(
                                    icon: "p.circle.fill",
                                    label: "E.FREN",
                                    dikCode: UInt8(NFSU2_DIK_SPACE),
                                    tintColor: .orange,
                                    size: actionSize
                                )
                            }
                            
                            // Ana Pedallar: Fren (Aşağı Ok / S) & Gaz (Yukarı Ok / W)
                            HStack(spacing: isPad ? 14 : 10) {
                                RacingPedalView(
                                    label: "FREN",
                                    subLabel: "GERİ",
                                    dikCode: UInt8(NFSU2_DIK_DOWN),
                                    secondaryDik: UInt8(NFSU2_DIK_S),
                                    tintColor: .red,
                                    size: brakeSize
                                )
                                
                                RacingPedalView(
                                    label: "GAZ",
                                    subLabel: "İLERİ",
                                    dikCode: UInt8(NFSU2_DIK_UP),
                                    secondaryDik: UInt8(NFSU2_DIK_W),
                                    tintColor: .mint,
                                    size: gasSize
                                )
                            }
                        }
                        .padding(.trailing, hPad)
                        .padding(.bottom, bPad)
                    }
                    .transition(.opacity.combined(with: .scale(scale: 0.95)))
                }
            }
        }
    }
}

// MARK: - NFSU2 Metal Render Yüzeyi (CAMetalLayer + CADisplayLink Köprüsü)

public final class NFSU2MetalRenderUIView: UIView {
    public override class var layerClass: AnyClass {
        CAMetalLayer.self
    }
    
    public var metalLayer: CAMetalLayer {
        layer as! CAMetalLayer
    }
    
    private var displayLink: CADisplayLink?
    
    public override init(frame: CGRect) {
        super.init(frame: frame)
        backgroundColor = .black
        isOpaque = true
        contentScaleFactor = UIScreen.main.scale
        
        let mtl = metalLayer
        mtl.pixelFormat = .bgra8Unorm
        mtl.framebufferOnly = false
        mtl.contentsGravity = .resizeAspect
        mtl.contentsScale = UIScreen.main.scale
        
        metal_init()
        metal_set_layer(Unmanaged.passUnretained(mtl).toOpaque())
        startDisplayLink()
        setupNotificationObservers()
    }
    
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }
    
    private func setupNotificationObservers() {
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(applicationDidEnterBackground),
            name: UIApplication.didEnterBackgroundNotification,
            object: nil
        )
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(applicationWillEnterForeground),
            name: UIApplication.willEnterForegroundNotification,
            object: nil
        )
    }
    
    @objc private func applicationDidEnterBackground() {
        stopDisplayLink()
        nfsu2_input_clear_all()
    }
    
    @objc private func applicationWillEnterForeground() {
        startDisplayLink()
    }
    
    public override func layoutSubviews() {
        super.layoutSubviews()
        let scale = UIScreen.main.scale
        metalLayer.contentsScale = scale
        let dw = UInt32(bounds.width * scale)
        let dh = UInt32(bounds.height * scale)
        if dw > 0 && dh > 0 {
            metalLayer.drawableSize = CGSize(width: CGFloat(dw), height: CGFloat(dh))
            metal_resize(dw, dh)
        }
    }
    
    private func startDisplayLink() {
        guard displayLink == nil else { return }
        let dl = CADisplayLink(target: self, selector: #selector(renderTick))
        dl.preferredFrameRateRange = CAFrameRateRange(minimum: 60, maximum: 120, preferred: 60)
        dl.add(to: .main, forMode: .common)
        displayLink = dl
    }
    
    private func stopDisplayLink() {
        displayLink?.invalidate()
        displayLink = nil
    }
    
    @objc private func renderTick() {
        _ = metal_render_frame()
    }
    
    deinit {
        stopDisplayLink()
        NotificationCenter.default.removeObserver(self)
    }
}

public struct NFSU2MetalSurfaceView: UIViewRepresentable {
    public init() {}
    
    public func makeUIView(context: Context) -> NFSU2MetalRenderUIView {
        NFSU2MetalRenderUIView(frame: .zero)
    }
    
    public func updateUIView(_ uiView: NFSU2MetalRenderUIView, context: Context) {}
}

// MARK: - GameMetalView (Metal Renderer + Dokunmatik Kontroller + GameController Entegrasyonu)

public struct GameMetalView: View {
    @Environment(\.scenePhase) private var scenePhase
    @StateObject private var controllerManager = GameControllerManager.shared
    @State private var showTouchOverlay: Bool = true
    
    // Kullanıcı kontrolcü bağlı olsa bile dokunmatiği zorla açabilir / kapatabilir
    @State private var userOverrideOverlay: Bool? = nil
    
    public init() {}
    
    public var body: some View {
        ZStack {
            // Arka plandaki Metal Görünümü (60-120 FPS native Metal render yüzeyi)
            NFSU2MetalSurfaceView()
                .ignoresSafeArea()
            
            // Üstteki Etkileşimli Kontrol Katmanı
            OnScreenControlsOverlay(showControls: Binding(
                get: {
                    if let overrideValue = userOverrideOverlay {
                        return overrideValue
                    }
                    // Kontrolcü bağlı ise dokunmatik kontroller otomatik gizlenir
                    return !controllerManager.isControllerConnected
                },
                set: { newValue in
                    userOverrideOverlay = newValue
                }
            ))
        }
        .onAppear {
            controllerManager.checkForExistingControllers()
        }
        .onDisappear {
            nfsu2_input_clear_all()
        }
        .onChange(of: scenePhase) { phase in
            if phase != .active {
                // Uygulama arka plana geçtiğinde veya kesintiye uğradığında takılı tuşları sıfırla
                nfsu2_input_clear_all()
            }
        }
        .onChange(of: controllerManager.isControllerConnected) { connected in
            // Fiziksel kontrolcü bağlandığında veya koptuğunda animasyonla dokunmatik katmanı güncelle
            withAnimation(.easeInOut(duration: 0.25)) {
                if connected {
                    userOverrideOverlay = nil // Otomatik moda dön ve gizle
                }
            }
        }
    }
}
