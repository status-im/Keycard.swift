enum AppStatusTag: UInt8 {
    case template = 0xA3
}

public struct ApplicationStatus {
    public let pinRetryCount: Int
    public let pukRetryCount: Int
    public let hasMasterKey: Bool
    
    public init(_ data: [UInt8]) throws {
        let tlv = TinyBERTLV(data)
        _ = try tlv.enterConstructed(tag: AppStatusTag.template.rawValue)
        pinRetryCount = try tlv.readInt()
        pukRetryCount = try tlv.readInt()
        hasMasterKey = try tlv.readBoolean()
    }
}
