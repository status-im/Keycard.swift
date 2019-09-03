/**
 * ISO7816-4 R-APDU.
 */
public struct APDUResponse {
    public let data: [UInt8]
    public let sw1: UInt8
    public let sw2: UInt8

    public var sw: UInt16 {
        get {
            return (UInt16(self.sw1) << 8) | UInt16(self.sw2)
        }
    }

    public init(rawData: [UInt8]) {
        precondition(rawData.count >= 2, "rawData must contain at least the Status Word (2 bytes)")
        self.sw1 = rawData[rawData.count - 2]
        self.sw2 = rawData[rawData.count - 1]
        self.data = rawData.count > 2 ? Array(rawData[0..<(rawData.count - 3)]) : []
    }
    
    public init(sw1: UInt8, sw2: UInt8, data: [UInt8]) {
        self.sw1 = sw1
        self.sw2 = sw2
        self.data = data
    }

    @discardableResult
    public func checkOK() throws -> APDUResponse {
        try checkSW(StatusWord.ok)
    }

    @discardableResult
    public func checkAuthOK() throws -> APDUResponse {
        if (self.sw & StatusWord.wrongPINMask.rawValue) == StatusWord.wrongPINMask.rawValue {
            throw CardError.wrongPIN(retryCounter: Int(self.sw2 & 0x0F))
        } else {
            return try checkOK()
        }
    }

    @discardableResult
    public func checkSW(_ codes: StatusWord...) throws -> APDUResponse {
        try checkSW(codes: codes.map({ $0.rawValue }))
    }

    @discardableResult
    public func checkSW(_ codes: UInt16...) throws -> APDUResponse {
        try checkSW(codes: codes)
    }

    @discardableResult
    public func checkSW(codes: [UInt16]) throws -> APDUResponse {
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
