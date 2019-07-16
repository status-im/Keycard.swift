class Crypto {
    static let shared = Crypto()
    
    private init() {
        
    }
    
    func hmacSHA512(data: [UInt8], key: [UInt8]) -> [UInt8] {
        [] //TODO: implement
    }
    
    func kekkac256(_ data: [UInt8]) -> [UInt8] {
        [] //TODO: implement
    }
    
    func secp256k1PublicToEthereumAddress(_ pubKey: [UInt8]) -> [UInt8] {
        Array(kekkac256(Array(pubKey[1...]))[12...])
    }
    
    func secp256k1PublicFromPrivate(_ privKey: [UInt8]) -> [UInt8] {
        [] //TODO: implement
    }
}
