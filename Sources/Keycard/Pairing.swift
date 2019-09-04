public struct Pairing {
    public let pairingKey: [UInt8]
    public let pairingIndex: UInt8

    public var bytes: [UInt8] {
        get {
            return [pairingIndex] + pairingKey
        }
    }

    public init(pairingKey: [UInt8], pairingIndex: UInt8) {
        self.pairingKey = pairingKey
        self.pairingIndex = pairingIndex
    }

    public init(pairingData: [UInt8]) {
        self.pairingIndex = pairingData[0]
        self.pairingKey = Array(pairingData[1...])
    }
}
