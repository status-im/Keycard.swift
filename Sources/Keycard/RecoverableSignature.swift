enum ECDSASignatureTag: UInt8 {
    case signatureTemplate = 0xA0
    case ecdsaTemplate = 0x30
}

public struct RecoverableSignature {
    public let publicKey: [UInt8]
    public let recId: UInt8
    public let r: [UInt8]
    public let s: [UInt8]
    
    public init(hash: [UInt8], data: [UInt8]) throws {
        let tlv = TinyBERTLV(data)
        _ = try tlv.enterConstructed(tag: ECDSASignatureTag.signatureTemplate.rawValue)
        self.publicKey = try tlv.readPrimitive(tag: AppInfoTag.pubKey.rawValue)
        _ = try tlv.enterConstructed(tag: ECDSASignatureTag.ecdsaTemplate.rawValue)
        self.r = try Util.shared.dropZeroPrefix(uint8: tlv.readPrimitive(tag: TLVTag.int.rawValue))
        self.s = try Util.shared.dropZeroPrefix(uint8: tlv.readPrimitive(tag: TLVTag.int.rawValue))
        
        var foundID: UInt8 = UInt8.max
        
        for i: UInt8 in 0...3 {
            let pub = Crypto.shared.secp256k1RecoverPublic(r: r, s: s, recId: i, hash: hash)
            if (pub == self.publicKey) {
                foundID = i
                break
            }
        }
        
        if (foundID != UInt8.max) {
            self.recId = foundID
        } else {
            throw CardError.unrecoverableSignature
        }
    }
}
