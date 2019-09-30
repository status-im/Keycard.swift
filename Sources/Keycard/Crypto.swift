import secp256k1
import CryptoSwift
import CommonCrypto
import Foundation

enum PBKDF2HMac {
    case sha256
    case sha512
}

class Crypto {
    static let shared = Crypto()
    
    let secp256k1Ctx: OpaquePointer
    
    private init() {
        secp256k1Ctx = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY))!
    }
    
    deinit {
        secp256k1_context_destroy(secp256k1Ctx)
    }
    
    func aes256Enc(data: [UInt8], iv: [UInt8], key: [UInt8]) -> [UInt8] {
        let result = try! AES(key: key, blockMode: CBC(iv: iv), padding: .noPadding).encrypt(data)
        Logger.shared.log("aes256Enc(data=\(Data(data).toHexString()) iv=\(Data(iv).toHexString()) key=\(Data(key).toHexString())) => \(Data(result).toHexString())")
        return result
    }
    
    func aes256Dec(data: [UInt8], iv: [UInt8], key: [UInt8]) -> [UInt8] {
        let result = try! AES(key: key, blockMode: CBC(iv: iv), padding: .noPadding).decrypt(data)
        Logger.shared.log("aes256Dec(data=\(Data(data).toHexString()) iv=\(Data(iv).toHexString()) key=\(Data(key).toHexString())) => \(Data(result).toHexString())")
        return result
    }
    
    func aes256CMac(data: [UInt8], key: [UInt8]) -> [UInt8] {
        let result = aes256Enc(data: data, iv: [UInt8](repeating: 0, count: SecureChannel.blockLength), key: key).suffix(16)
        assert(result.count == 16, "CMac must be 16 bytes long but it is \(result.count)")
        return Array(result)
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

    func pbkdf2(password: String, salt: [UInt8], iterations requiredIterations: Int? = nil, hmac: PBKDF2HMac) -> [UInt8] {
        // implemented using CommonCrypto because it is much faster (ms vs s) on the device than CryptoSwfit implementation.
        let keyLength: Int
        let prf: CCPseudoRandomAlgorithm

        switch hmac {
        case .sha256:
            keyLength = 32
            prf = CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256)
        case .sha512:
            keyLength = 64
            prf = CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA512)
        }

        precondition(salt.count < 133, "Salt must be less than 133 bytes length")
        var saltBytes = salt
        var passwordBytes = [UInt8](password.utf8).map { Int8(exactly: $0)! }
        let timeMsec: UInt32 = 500
        let iterations = CCCalibratePBKDF(CCPBKDFAlgorithm(kCCPBKDF2),
                                          passwordBytes.count,
                                          saltBytes.count,
                                          prf,
                                          keyLength,
                                          timeMsec)
        if iterations == .max {
            preconditionFailure("PBKDF Calibration error")
        }
        let pbkdfIterations = requiredIterations == nil ? iterations : UInt32(requiredIterations!)
        var outKey: [UInt8] = [UInt8](repeating: 0, count: keyLength)
        let result = CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2),
                                          &passwordBytes,
                                          passwordBytes.count,
                                          &saltBytes,
                                          saltBytes.count,
                                          prf,
                                          pbkdfIterations,
                                          &outKey,
                                          keyLength)
        if result == kCCParamError {
            preconditionFailure("PBKDF error")
        }
        return outKey
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
        } while secp256k1_ec_seckey_verify(secp256k1Ctx, &secretKey) != Int32(1)

        return (secretKey, secp256k1PublicFromPrivate(secretKey))
    }
    
    func secp256k1ECDH(privKey: [UInt8], pubKey pubKeyBytes: [UInt8]) -> [UInt8] {
        var pubKey = secp256k1_pubkey()
        var ecdhOut = [UInt8](repeating: 0, count: 32)
        _ = secp256k1_ec_pubkey_parse(secp256k1Ctx, &pubKey, pubKeyBytes, pubKeyBytes.count)
        _ = secp256k1_ecdh(secp256k1Ctx, &ecdhOut, &pubKey, privKey, { (output, x, _, _) -> Int32 in memcpy(output, x, 32); return 1 }, nil)
        
        return ecdhOut
    }
    
    func secp256k1PublicToEthereumAddress(_ pubKey: [UInt8]) -> [UInt8] {
        Array(keccak256(Array(pubKey[1...]))[12...])
    }
    
    func secp256k1PublicFromPrivate(_ privKey: [UInt8]) -> [UInt8] {
        var pubKey = secp256k1_pubkey()
        _ = secp256k1_ec_pubkey_create(secp256k1Ctx, &pubKey, privKey)
        return _secp256k1PubToBytes(&pubKey)
    }
    
    func secp256k1RecoverPublic(r: [UInt8], s: [UInt8], recId: UInt8, hash: [UInt8]) -> [UInt8] {
        var sig = secp256k1_ecdsa_recoverable_signature()
        _ = secp256k1_ecdsa_recoverable_signature_parse_compact(secp256k1Ctx, &sig, r + s, Int32(recId))
        
        var pubKey = secp256k1_pubkey()
        _ = secp256k1_ecdsa_recover(secp256k1Ctx, &pubKey, &sig, hash)
        return _secp256k1PubToBytes(&pubKey)
    }
    
    func secp256k1Sign(hash: [UInt8], privKey: [UInt8]) -> [UInt8] {
        var sig = secp256k1_ecdsa_signature()

        _ = secp256k1_ecdsa_sign(secp256k1Ctx, &sig, hash, privKey, nil, nil)
        var derSig = [UInt8](repeating: 0, count: 72)
        var derOutLen = 72

        secp256k1_ecdsa_signature_serialize_der(secp256k1Ctx, &derSig, &derOutLen, &sig)
        return Array(derSig[0..<derOutLen])
    }
    
    private func _secp256k1PubToBytes(_ pubKey: inout secp256k1_pubkey) -> [UInt8] {
        var pubKeyBytes = [UInt8](repeating: 0, count: 65)
        var outputLen = 65
        _ = secp256k1_ec_pubkey_serialize(secp256k1Ctx, &pubKeyBytes, &outputLen, &pubKey, UInt32(SECP256K1_EC_UNCOMPRESSED))
        
        return pubKeyBytes
    }
    
    func random(count: Int) -> [UInt8] {
        AES.randomIV(count)
    }
}
