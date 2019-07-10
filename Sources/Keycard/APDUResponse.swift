/**
 * ISO7816-4 R-APDU.
 */
struct APDUResponse {
    let data: [UInt8]
    let sw1: UInt8
    let sw2: UInt8

    var sw: UInt16 {
        get {
            return (UInt16(self.sw1) << 8) | UInt16(self.sw2)
        }
    }

    init(rawData: [UInt8]) {
        precondition(rawData.count >= 2, "rawData must contain at least the Status Word (2 bytes)")
        self.sw1 = rawData[rawData.count - 2]
        self.sw2 = rawData[rawData.count - 1]
        self.data = rawData.count > 2 ? Array(rawData[0...(rawData.count - 3)]) : []
    }

    func checkOK() throws -> APDUResponse {
        try checkSW(StatusWord.ok)
    }

    func checkAuthOK() throws -> APDUResponse {
        if (self.sw & StatusWord.wrongPINMask.rawValue) == StatusWord.wrongPINMask.rawValue {
            throw CardError.wrongPIN(retryCounter: Int(self.sw2 & 0x0F))
        } else {
            return try checkOK()
        }
    }

    func checkSW(_ codes: StatusWord...) throws -> APDUResponse {
        try checkSW(codes: codes.map({ $0.rawValue }))
    }

    func checkSW(_ codes: UInt16...) throws -> APDUResponse {
        try checkSW(codes: codes)
    }

    func checkSW(codes: [UInt16]) throws -> APDUResponse {
        for code in codes {
            if (self.sw == code) {
                return self;
            }
        }

        if let aSW = StatusWord(rawValue: self.sw) {
            throw aSW
        } else {
            throw StatusWord.unknownError
        }
    }
}
