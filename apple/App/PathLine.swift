import SwiftUI

/// What a path line shows about one device, from the node's own view.
struct PathLineModel: Equatable {
    /// A NAT on the line: a tick, in the secondary colour when it cannot be punched.
    struct Tick: Equatable {
        var punchable: Bool
    }

    enum Shape: Equatable {
        case idle
        case connecting
        case local
        case internet(this: Tick?, peer: Tick?)
        /// Through a server of the cloud; `name` is "Switch" or "Relay".
        case helper(name: String)
    }

    var shape: Shape
    /// The smoothed round trip in milliseconds.
    var rtt: Int?
    var name: String

    init(_ device: Device) {
        name = device.name
        rtt = device.paths?.rtt
        switch device.route {
        case .idle: shape = .idle
        case .connecting: shape = .connecting
        case .direct(onLAN: true): shape = .local
        case .direct(onLAN: false): shape = .internet(this: Self.thisTick(device), peer: Self.peerTick(device))
        case .helper(let kind): shape = .helper(name: kind == "switch" ? "Switch" : "Relay")
        }
    }

    /// This node's NAT in the family of the route, or the better of the two when the route has no address.
    private static func thisTick(_ device: Device) -> Tick? {
        guard let local = device.local else { return nil }
        let nat: PathView.Nat
        if let addr = device.paths?.route?.addr {
            nat = addr.hasPrefix("[") ? local.ipv6 : local.ipv4
        } else {
            nat = [local.ipv4, local.ipv6].first { $0.nat == "punchable" } ?? local.ipv4
        }
        return nat.nat == "unknown" ? nil : Tick(punchable: nat.nat == "punchable")
    }

    private static func peerTick(_ device: Device) -> Tick? {
        switch device.paths?.nat {
        case "punchable": Tick(punchable: true)
        case "relay_only": Tick(punchable: false)
        default: nil
        }
    }

    var rttText: String? { rtt.map { $0 == 0 ? "<1 ms" : "\($0) ms" } }

    /// "Phone: direct through the internet, 12 ms".
    var summary: String {
        var parts: String
        switch shape {
        case .idle: parts = "not connected"
        case .connecting: parts = "connecting"
        case .local: parts = "direct on the local network"
        case .internet(let this, let peer):
            parts = "direct through the internet"
            let limited = [this, peer].contains { $0?.punchable == false }
            if limited { parts += ", a NAT that cannot be punched" }
        case .helper(let name): parts = "through a \(name.lowercased()), metered"
        }
        if let text = rttText { parts += ", \(text)" }
        return "\(name): \(parts)"
    }
}

/// This node, one line and the device, all at the height of the end circles. The line says how
/// the device is reached: straight on the local network, through the internet past the NATs (a
/// cloud in the line, the RTT inside it, and a tick per NAT), or through a switch or a relay of the
/// cloud (orange and dashed, the cloud, then its name and the RTT).
struct PathLine: View {
    enum Size {
        case compact, regular, large

        var circle: CGFloat { self == .compact ? 28 : self == .regular ? 34 : 44 }
        var tick: CGFloat { self == .compact ? 10 : self == .regular ? 12 : 16 }
        var width: CGFloat { self == .large ? 2.5 : 2 }
        var font: Font { self == .large ? .footnote : .caption }
    }

    let device: Device
    var size = Size.regular

    private var model: PathLineModel { PathLineModel(device) }
    private var color: Color { device.route.color }

    var body: some View {
        HStack(spacing: 0) {
            endpoint("You")
            segment(tick: ticks.this, at: 0.35)
            label
            segment(tick: ticks.peer, at: 0.65)
            endpoint(device.initial)
        }
        .frame(height: size.circle)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(model.summary)
    }

    private var ticks: (this: PathLineModel.Tick?, peer: PathLineModel.Tick?) {
        if case .internet(let this, let peer) = model.shape { return (this, peer) }
        return (nil, nil)
    }

    private func endpoint(_ text: String) -> some View {
        Text(text)
            .font(size == .compact ? .caption2.weight(.semibold) : .caption.weight(.semibold))
            .frame(width: size.circle, height: size.circle)
            .overlay(Circle().strokeBorder(.secondary, lineWidth: 1.5))
    }

    private var stroke: StrokeStyle {
        switch model.shape {
        case .local, .internet: StrokeStyle(lineWidth: size.width, lineCap: .round)
        case .idle, .connecting, .helper: StrokeStyle(lineWidth: size.width, lineCap: .round, dash: [5, 4])
        }
    }

    /// Half of the line, with a NAT's tick at `at` of its width.
    private func segment(tick: PathLineModel.Tick?, at fraction: CGFloat) -> some View {
        Canvas { ctx, canvas in
            let y = canvas.height / 2
            var path = Path()
            path.move(to: CGPoint(x: 0, y: y))
            path.addLine(to: CGPoint(x: canvas.width, y: y))
            ctx.stroke(path, with: .color(color), style: stroke)
            guard let tick else { return }
            let x = canvas.width * fraction
            var mark = Path()
            mark.move(to: CGPoint(x: x, y: y - size.tick / 2))
            mark.addLine(to: CGPoint(x: x, y: y + size.tick / 2))
            ctx.stroke(
                mark, with: .color(tick.punchable ? color : Color.secondary),
                style: StrokeStyle(lineWidth: size.width + 0.5, lineCap: .round))
        }
        .frame(minWidth: 16)
    }

    /// The way and the RTT, on the line: "Local · 3 ms"; a cloud with the RTT inside; or an empty
    /// cloud and "Relay · 40 ms".
    @ViewBuilder
    private var label: some View {
        switch model.shape {
        case .idle: text("Not connected")
        case .connecting: text("Connecting")
        case .local: text(joined("Local"))
        case .internet: cloud(rtt: true)
        case .helper(let name):
            HStack(spacing: 0) {
                cloud(rtt: false)
                text(joined(name))
            }
        }
    }

    private func text(_ text: String) -> some View {
        Text(text)
            .font(size.font.weight(.medium))
            .monospacedDigit()
            .foregroundStyle(model.shape == .idle || model.shape == .connecting ? Color.secondary : color)
            .lineLimit(1)
            .fixedSize()
            .padding(.horizontal, 6)
    }

    /// The internet, with the RTT inside if `rtt`.
    private func cloud(rtt: Bool) -> some View {
        ZStack {
            Image(systemName: "cloud").font(.system(size: size.circle * 1.32, weight: .thin))
            if rtt, let rtt = model.rttText {
                Text(rtt)
                    .font(.system(size: size.circle * 0.25, weight: .semibold))
                    .monospacedDigit()
                    .offset(y: size.circle * 0.1)
            }
        }
        .foregroundStyle(color)
        .frame(height: size.circle)
        .fixedSize()
        .padding(.horizontal, 2)
    }

    private func joined(_ text: String) -> String {
        model.rttText.map { "\(text) · \($0)" } ?? text
    }
}
