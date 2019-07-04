/**
 * ISO7816-4 R-APDU.
 */
struct APDUResponse {
    let data : [UInt8]
    let sw1 : UInt8
    let sw2 : UInt8
    
    var sw : UInt16 {
        get {
            (UInt16(self.sw1) << 8) | UInt16(self.sw2)
        }
    }
    
    init(rawData: [UInt8]) {
        precondition(rawData.count >= 2, "rawData must contain at least the Status Word (2 bytes)")
        self.sw1 = rawData[rawData.count - 2]
        self.sw2 = rawData[rawData.count - 1]
        self.data = rawData.count > 2 ? Array(rawData[0...(rawData.count - 3)]) : []
    }
}
