enum CashAppInfoTag: UInt8 {
    case template = 0xA4
    case pubKey = 0x80
    case pubData = 0x82
}

public struct CashApplicationInfo {
    public let pubKey: [UInt8]
    public let appVersion: UInt16
    public let pubData: [UInt8]
    
    public var appVersionString: String {
        return "\(appVersion >> 8).\(appVersion & 0xff)"
    }
    
    public init(_ data: [UInt8]) throws {
        let tlv = TinyBERTLV(data)
        
        _ = try tlv.enterConstructed(tag: CashAppInfoTag.template.rawValue)
        pubKey = try tlv.readPrimitive(tag: CashAppInfoTag.pubKey.rawValue)
        appVersion = try UInt16(tlv.readInt())
        pubData = try tlv.readPrimitive(tag: CashAppInfoTag.pubData.rawValue)
    }
    
    public init(pubKey: [UInt8], appVersion: UInt16, pubData: [UInt8]) {
        self.pubKey = pubKey
        self.appVersion = appVersion
        self.pubData = pubData
    }
    
}
