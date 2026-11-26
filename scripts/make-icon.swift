// 生成 App 图标：深青到冰川蓝的圆角底 + 盾牌符号。用法：swift make-icon.swift <输出目录.iconset>
import AppKit

let out = CommandLine.arguments[1]
try? FileManager.default.createDirectory(atPath: out, withIntermediateDirectories: true)

func render(_ px: Int) -> Data {
    let size = CGFloat(px)
    let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: px, pixelsHigh: px, bitsPerSample: 8,
                               samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB,
                               bytesPerRow: 0, bitsPerPixel: 0)!
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
    let inset = size * 0.1
    let rect = NSRect(x: inset, y: inset, width: size - inset * 2, height: size - inset * 2)
    let path = NSBezierPath(roundedRect: rect, xRadius: rect.width * 0.225, yRadius: rect.width * 0.225)
    NSGradient(colors: [NSColor(srgbRed: 0.02, green: 0.24, blue: 0.33, alpha: 1),
                        NSColor(srgbRed: 0.10, green: 0.62, blue: 0.72, alpha: 1)])!.draw(in: path, angle: 70)
    NSColor.white.withAlphaComponent(0.18).setStroke()
    path.lineWidth = max(1, size * 0.006)
    path.stroke()
    let cfg = NSImage.SymbolConfiguration(pointSize: size * 0.42, weight: .semibold)
        .applying(.init(paletteColors: [.white, NSColor(srgbRed: 0.55, green: 0.95, blue: 0.85, alpha: 1)]))
    if let sym = NSImage(systemSymbolName: "checkmark.shield.fill", accessibilityDescription: nil)?.withSymbolConfiguration(cfg) {
        let s = sym.size
        sym.draw(in: NSRect(x: (size - s.width) / 2, y: (size - s.height) / 2, width: s.width, height: s.height))
    }
    NSGraphicsContext.restoreGraphicsState()
    return rep.representation(using: .png, properties: [:])!
}

for base in [16, 32, 128, 256, 512] {
    try! render(base).write(to: URL(fileURLWithPath: "\(out)/icon_\(base)x\(base).png"))
    try! render(base * 2).write(to: URL(fileURLWithPath: "\(out)/icon_\(base)x\(base)@2x.png"))
}
