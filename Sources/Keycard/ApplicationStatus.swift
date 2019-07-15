enum AppStatusTag: UInt8 {
    case template = 0xA3
}

struct ApplicationStatus {
    let pinRetryCount: Int
    let pukRetryCount: Int
    let hasMasterKey: Bool
    
    init(_ data: [UInt8]) throws {
        let tlv = TinyBERTLV(data)
        _ = try tlv.enterConstructed(tag: AppStatusTag.template.rawValue)
        pinRetryCount = try tlv.readInt()
        pukRetryCount = try tlv.readInt()
        hasMasterKey = try tlv.readBoolean()
    }
}
