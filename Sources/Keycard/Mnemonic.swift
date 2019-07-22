import Foundation

struct Mnemonic {
    static let bip39IterationCount = 2048
    
    static func toBinarySeed(mnemonicPhrase: String, password: String = "") -> [UInt8] {
        Crypto.shared.pbkdf2(password: mnemonicPhrase, salt: Array(("mnemonic" + password).utf8), iterations: Mnemonic.bip39IterationCount, hmac: PBKDF2HMac.sha512)
    }
    
    let indexes: [UInt16]
    var words: [String] {
        get {
            precondition(wordList != nil)
            return self.indexes.map { (idx) -> String in
                self.wordList![Int(idx)]
            }
        }
    }
    
    var wordList: [String]?
    
    init(rawData: [UInt8]) {
        var idx: [UInt16] = []
        
        for i in 0..<(rawData.count / 2) {
            idx.append((UInt16(rawData[i * 2] << 8)) | UInt16(rawData[(i * 2) + 1]))
        }
        
        self.indexes = idx
    }
    
    mutating func useBIP39EnglishWordlist() {
        let path = Bundle.main.path(forResource: "english", ofType: "txt")!
        let content = try! String(contentsOfFile: path, encoding: String.Encoding.utf8)
        self.wordList = content.split(separator: "\n").map {(s) -> String in String(s) }
    }
    
    func toMnemonicPhrase() -> String {
        self.words.joined(separator: " ")
    }
    
    func toBinarySeed(password: String = "") -> [UInt8] {
        Mnemonic.toBinarySeed(mnemonicPhrase: toMnemonicPhrase(), password: password)
    }
    
    func toBIP32KeyPair(password: String = "") -> BIP32KeyPair {
        BIP32KeyPair(fromSeed: toBinarySeed(password: password))
    }
}
