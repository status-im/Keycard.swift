import secp256k1
import CryptoSwift
    
enum PBKDF2HMac {
    case sha256
    case sha512
}

class Crypto {
    static let shared = Crypto()
    
    let ctx: OpaquePointer
    
    private init() {
        ctx = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY))!
    }
    
    deinit {
        secp256k1_context_destroy(ctx)
    }
    
    func aes256Enc(data: [UInt8], iv: [UInt8], key: [UInt8]) -> [UInt8] {
        try! AES(key: key, blockMode: CBC(iv: iv), padding: .noPadding).encrypt(data)
    }
    
    func aes256Dec(data: [UInt8], iv: [UInt8], key: [UInt8]) -> [UInt8] {
        try! AES(key: key, blockMode: CBC(iv: iv), padding: .noPadding).decrypt(data)
    }
    
    func aes256CMac(data: [UInt8], key: [UInt8]) -> [UInt8] {
        try! CBCMAC(key: key).authenticate(data)
    }
    
    func iso7816_4Pad(data: [UInt8], blockSize: Int) -> [UInt8] {
        var padded = Array(data)
        padded.append(0x80)
        
        // can be obviously optimized, but I really doubt it makes sense, and this is easier to read
        while (padded.count % blockSize) != 0 {
            padded.append(0x00)
        }
        
        return padded
    }
    
    func iso7816_4Unpad(data: [UInt8]) -> [UInt8] {
        if let idx = data.lastIndex(of: 0x80) {
            return Array(data[..<idx])
        } else {
            return data
        }
    }
    
    func pbkdf2(password: String, salt: [UInt8], iterations: Int, hmac: PBKDF2HMac) -> [UInt8] {
        let keyLength: Int
        let variant: HMAC.Variant
        
        switch hmac {
        case .sha256:
            keyLength = 32
            variant = .sha256
        case .sha512:
            keyLength = 64
            variant = .sha512
        }

        return try! PKCS5.PBKDF2(password: Array(password.utf8), salt: salt, iterations: iterations, keyLength: keyLength, variant: variant).calculate()
    }
    
    func hmacSHA512(data: [UInt8], key: [UInt8]) -> [UInt8] {
        return try! HMAC(key: key, variant: .sha512).authenticate(data)
    }
  
    func sha256(_ data: [UInt8]) -> [UInt8] {
        Digest.sha256(data)
    }
    
    func sha512(_ data: [UInt8]) -> [UInt8] {
        Digest.sha512(data)
    }
    
    func keccak256(_ data: [UInt8]) -> [UInt8] {
        Digest.sha3(data, variant: .keccak256)
    }

    func secp256k1GeneratePair() -> ([UInt8], [UInt8]) {
        var secretKey: [UInt8]
        
        repeat {
            secretKey = random(count: 32)
        } while secp256k1_ec_seckey_verify(ctx, &secretKey) != Int32(1)
        
        
        return (secretKey, secp256k1PublicFromPrivate(secretKey))
    }
    
    func secp256k1ECDH(privKey: [UInt8], pubKey pubKeyBytes: [UInt8]) -> [UInt8] {
        var pubKey = secp256k1_pubkey()
        var ecdhOut = [UInt8](repeating: 0, count: 32)
        _ = secp256k1_ec_pubkey_parse(ctx, &pubKey, pubKeyBytes, pubKeyBytes.count)
        _ = secp256k1_ecdh(ctx, &ecdhOut, &pubKey, privKey, { (output, x, _, _) -> Int32 in memcpy(output, x, 32); return 1 }, nil)
        
        return ecdhOut
    }
    
    func secp256k1PublicToEthereumAddress(_ pubKey: [UInt8]) -> [UInt8] {
        Array(keccak256(Array(pubKey[1...]))[12...])
    }
    
    func secp256k1PublicFromPrivate(_ privKey: [UInt8]) -> [UInt8] {
        var pubKey = secp256k1_pubkey()
        _ = secp256k1_ec_pubkey_create(ctx, &pubKey, privKey)
        return _secp256k1PubToBytes(&pubKey)
    }
    
    func secp256k1RecoverPublic(r: [UInt8], s: [UInt8], recId: UInt8, hash: [UInt8]) -> [UInt8] {
        var sig = secp256k1_ecdsa_recoverable_signature()
        _ = secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, &sig, r + s, Int32(recId))
        
        var pubKey = secp256k1_pubkey()
        _ = secp256k1_ecdsa_recover(ctx, &pubKey, &sig, hash)
        return _secp256k1PubToBytes(&pubKey)
    }
    
    private func _secp256k1PubToBytes(_ pubKey: inout secp256k1_pubkey) -> [UInt8] {
        var pubKeyBytes = [UInt8](repeating: 0, count: 65)
        var outputLen = 65
        _ = secp256k1_ec_pubkey_serialize(ctx, &pubKeyBytes, &outputLen, &pubKey, UInt32(SECP256K1_EC_UNCOMPRESSED))
        
        return pubKeyBytes
    }
    
    func random(count: Int) -> [UInt8] {
        AES.randomIV(count)
    }
}
