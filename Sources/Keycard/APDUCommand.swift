/**
 * ISO7816-4 APDU.
 */
public struct APDUCommand {
    public let cla: UInt8
    public let ins: UInt8
    public let p1: UInt8
    public let p2: UInt8
    public let data: [UInt8]
    public let needsLE: Bool

    public init(cla: UInt8, ins: UInt8, p1: UInt8, p2: UInt8, data: [UInt8] = [], needsLE: Bool = false) {
        self.cla = cla
        self.ins = ins
        self.p1 = p1
        self.p2 = p2
        self.data = data
        self.needsLE = needsLE
    }

    public func serialize() -> [UInt8] {
        let header = [cla, ins, p1, p2, UInt8(data.count)]
        let footer = needsLE ? [UInt8(0)] : []
        return header + data + footer
    }
}
