import XCTest
@testable import Keycard

final class CryptoTests: XCTestCase {
    func testAES() {
        let plaintext = "Hello, World!"
        let plaintextBytes = [UInt8](plaintext.utf8)

        let (sk, pk) = Crypto.shared.secp256k1GeneratePair()
        let secret = Crypto.shared.secp256k1ECDH(privKey: sk, pubKey: pk)
        let iv = Crypto.shared.random(count: SecureChannel.blockLength)
        let encrypted = Crypto.shared.aes256Enc(data: Crypto.shared.iso7816_4Pad(data: plaintextBytes, blockSize: SecureChannel.blockLength), iv: iv, key: secret)
        let decrypted = Crypto.shared.iso7816_4Unpad(data: Crypto.shared.aes256Dec(data: encrypted, iv: iv, key: secret))

        let decryptedText = String(data: Data(decrypted), encoding: .utf8)
        XCTAssertEqual(decryptedText, plaintext)
    }

    func testDES() {
        let plaintext = "Hello, World!"
        let paddedData = Crypto.shared.iso7816_4Pad(data: [UInt8](plaintext.utf8), blockSize: 8)
        
        let iv = Crypto.shared.random(count: 8)
        let key = GlobalPlatformKeys.statusKeys.val

        let encrypted = Crypto.shared.desEnc(data: paddedData, iv: iv, key: Crypto.shared.resizeDESKey8(key))
        let decrypted = Crypto.shared.desDec(data: encrypted, iv: iv, key: Crypto.shared.resizeDESKey8(key))
        XCTAssertEqual(decrypted, paddedData)
        
        let encrypted3 = Crypto.shared.des3Enc(data: paddedData, iv: iv, key: key)
        let decrypted3 = Crypto.shared.des3Dec(data: encrypted3, iv: iv, key: key)
        XCTAssertEqual(decrypted3, paddedData)
        
        let mac = Crypto.shared.des3Mac(data: paddedData, iv: iv, key: key)
        XCTAssertEqual(encrypted3.suffix(8), mac)
        
        let fullMac = Crypto.shared.des3FullMac(data: paddedData, iv: iv, key: key)
        XCTAssertEqual(fullMac.count, 8)
    }
}
