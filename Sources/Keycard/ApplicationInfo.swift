enum AppInfoTag: UInt8 {
    case template = 0x04
    case pubKey = 0x80
    case uid = 0x8f
    case keyUID = 0x8e
    case capabilities = 0x8d
}

enum AppCapability: UInt8 {
    case secureChannel = 0x01
    case keyManagement = 0x02
    case credentialsManagement = 0x04
    case ndef = 0x08
    case all = 0x0f
}

struct ApplicationInfo {
    let instanceUID: [UInt8]
    let freePairingSlots : Int
    let appVersion : UInt16
    let keyUID: [UInt8]
    let secureChannelPubKey: [UInt8]
    let initializedCard: Bool
    let capabilities: UInt8
    
    init(_ data: [UInt8]) throws {
        let tlv = TinyBERTLV(data)
        let topTag = try tlv.readTag()
        tlv.unreadLastTag()
        
        if (topTag == AppInfoTag.pubKey.rawValue) {
            secureChannelPubKey = try tlv.readPrimitive(tag: AppInfoTag.pubKey.rawValue)
            initializedCard = false
            
            if (secureChannelPubKey.count > 0) {
                capabilities = AppCapability.credentialsManagement.rawValue | AppCapability.secureChannel.rawValue
            } else {
                capabilities = AppCapability.credentialsManagement.rawValue
            }
            
            instanceUID = []
            freePairingSlots = 0
            appVersion = 0
            keyUID = []
            
            return
        }
        
        _ = try tlv.enterConstructed(tag: AppInfoTag.template.rawValue)
        instanceUID = try tlv.readPrimitive(tag: AppInfoTag.uid.rawValue)
        secureChannelPubKey = try tlv.readPrimitive(tag: AppInfoTag.pubKey.rawValue)
        appVersion = try UInt16(tlv.readInt())
        freePairingSlots = try tlv.readInt()
        keyUID = try tlv.readPrimitive(tag: AppInfoTag.keyUID.rawValue)
        
        do {
            capabilities = try tlv.readPrimitive(tag: AppInfoTag.capabilities.rawValue)[0]
        } catch TLVError.endOfTLV {
            capabilities = AppCapability.all.rawValue
        }
        
        initializedCard = true
    }
    
    var appVersionString: String { get { "\(appVersion >> 8).\(appVersion & 0xff)" } }
    var hasMasterKey: Bool { get { keyUID.count > 0 } }
    var hasSecureChannelCapability: Bool { get { (capabilities & AppCapability.secureChannel.rawValue) != 0 } }
    var hasKeyManagementCapability: Bool { get { (capabilities & AppCapability.keyManagement.rawValue) != 0 } }
    var hasCredentialsManagementCapability: Bool { get { (capabilities & AppCapability.credentialsManagement.rawValue) != 0 } }
    var hasNDEFCapability: Bool { get { (capabilities & AppCapability.ndef.rawValue) != 0 } }
}
