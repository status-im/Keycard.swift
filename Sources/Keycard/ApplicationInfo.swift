enum AppInfoTag: UInt8 {
    case template = 0xA4
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

public struct ApplicationInfo {

    public let instanceUID: [UInt8]
    public let freePairingSlots: Int
    public let appVersion: UInt16
    public let keyUID: [UInt8]
    public let secureChannelPubKey: [UInt8]
    public let initializedCard: Bool
    public let capabilities: UInt8

    public var appVersionString: String {
        return "\(appVersion >> 8).\(appVersion & 0xff)"
    }

    public var hasMasterKey: Bool {
        return keyUID.count > 0
    }

    public var hasSecureChannelCapability: Bool {
        return (capabilities & AppCapability.secureChannel.rawValue) != 0
    }

    public var hasKeyManagementCapability: Bool {
        return (capabilities & AppCapability.keyManagement.rawValue) != 0
    }

    public var hasCredentialsManagementCapability: Bool {
        return (capabilities & AppCapability.credentialsManagement.rawValue) != 0
    }

    public var hasNDEFCapability: Bool {
        return (capabilities & AppCapability.ndef.rawValue) != 0
    }

    public init(_ data: [UInt8]) throws {
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

    public init(instanceUID: [UInt8],
                freePairingSlots: Int,
                appVersion: UInt16,
                keyUID: [UInt8],
                secureChannelPubKey: [UInt8],
                initializedCard: Bool,
                capabilities: UInt8) {
        self.instanceUID = instanceUID
        self.freePairingSlots = freePairingSlots
        self.appVersion = appVersion
        self.keyUID = keyUID
        self.secureChannelPubKey = secureChannelPubKey
        self.initializedCard = initializedCard
        self.capabilities = capabilities
    }

}
