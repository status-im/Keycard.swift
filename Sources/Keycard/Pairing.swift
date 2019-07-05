struct Pairing {
    let pairingKey: [UInt8]
    let pairingIndex: UInt8
    
    init(pairingKey: [UInt8], pairingIndex: UInt8) {
        self.pairingKey = pairingKey
        self.pairingIndex = pairingIndex
    }
    
    init(pairingData: [UInt8]) {
        self.pairingIndex = pairingData[0]
        self.pairingKey = Array(pairingData[1...(pairingData.count - 1)])
    }
    
    var bytes: [UInt8] {
        get {
            [pairingIndex] + pairingKey
        }
    }
}
