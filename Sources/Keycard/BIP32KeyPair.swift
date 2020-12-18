public enum BIP32KeyTag: UInt8 {
    case template = 0xA1
    case pubKey = 0x80
    case privKey = 0x81
    case chainCode = 0x82
}

public struct BIP32KeyPair {
    public let privateKey: [UInt8]?
    public let chainCode: [UInt8]?
    public let publicKey: [UInt8]
    
    public var isPublicOnly: Bool { get { privateKey == nil } }
    public var isExtended: Bool { get { chainCode != nil } }
    
    public init(privateKey: [UInt8]?, chainCode: [UInt8]?, publicKey: [UInt8]?) {
        precondition(privateKey != nil || (chainCode == nil && publicKey != nil))
        
        if (privateKey != nil) {
            self.privateKey = Util.shared.dropZeroPrefix(uint8: privateKey!)
        } else {
            self.privateKey = privateKey
        }
        
        self.chainCode = chainCode
        
        if let pubKey = publicKey {
            self.publicKey = pubKey
        } else {
            self.publicKey = Crypto.shared.secp256k1PublicFromPrivate(privateKey!)
        }
    }
    
    public init(fromSeed binarySeed: [UInt8]) {
        let mac = Crypto.shared.hmacSHA512(data: binarySeed, key: Array("Bitcoin seed".utf8))
        self.init(privateKey: Array(mac[0..<32]), chainCode: Array(mac[32...]), publicKey: nil)
    }
    
    public init(fromTLV tlvData: [UInt8]) throws {
        let tlv = TinyBERTLV(tlvData)
        _ = try tlv.enterConstructed(tag: BIP32KeyTag.template.rawValue)
        
        let privKey: [UInt8]?
        let chain: [UInt8]?
        let pubKey: [UInt8]?
        
        var tag = try tlv.readTag()
        
        if (tag == BIP32KeyTag.pubKey.rawValue) {
            tlv.unreadLastTag()
            pubKey = try tlv.readPrimitive(tag: BIP32KeyTag.pubKey.rawValue)
            
            do {
                tag = try tlv.readTag()
            } catch(TLVError.endOfTLV) {
                tag = BIP32KeyTag.pubKey.rawValue
            }
        } else {
            pubKey = nil
        }
        
        if (tag == BIP32KeyTag.privKey.rawValue) {
            tlv.unreadLastTag()
            privKey = try tlv.readPrimitive(tag: BIP32KeyTag.privKey.rawValue)
            
            do {
                chain = try tlv.readPrimitive(tag: BIP32KeyTag.chainCode.rawValue)
            } catch (TLVError.endOfTLV) {
                chain = nil
            }
            
        } else {
            privKey = nil
            chain = nil
        }
        
        self.init(privateKey: privKey, chainCode: chain, publicKey: pubKey)
    }
    
    public func toTLV(includePublic: Bool = true) -> [UInt8] {
        var totalLength = 0
        
        totalLength += includePublic ? publicKey.count + 2 : 0
        totalLength += self.isPublicOnly ? 0 : privateKey!.count + 2
        totalLength += self.isExtended ? chainCode!.count + 2 : 0
        
        var data: [UInt8] = [BIP32KeyTag.template.rawValue]

        if (totalLength > 127) {
            data.append(UInt8(0x81))
        }
        
        data.append(UInt8(totalLength))
        
        if (includePublic) {
            data.append(BIP32KeyTag.pubKey.rawValue)
            data.append(UInt8(publicKey.count))
            data.append(contentsOf: publicKey)
        }
        
        if (!isPublicOnly) {
            data.append(BIP32KeyTag.privKey.rawValue)
            data.append(UInt8(privateKey!.count))
            data.append(contentsOf: privateKey!)
        }
        
        if (isExtended) {
            data.append(BIP32KeyTag.chainCode.rawValue)
            data.append(UInt8(chainCode!.count))
            data.append(contentsOf: chainCode!)
        }
        
        return data
    }
    
    public func toEthereumAddress() -> [UInt8] {
        Crypto.shared.secp256k1PublicToEthereumAddress(self.publicKey)
    }
}
