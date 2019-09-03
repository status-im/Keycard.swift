import XCTest
@testable import Keycard

final class CryptoTests: XCTestCase {

    func test_encrypt_decrypt() {
        let plaintext = "Hello, World!"
        let plaintextBytes = [UInt8](plaintext.utf8)

        let (sk, pk) = Crypto.shared.secp256k1GeneratePair()
        let secret = Crypto.shared.secp256k1ECDH(privKey: sk, pubKey: pk)
        let iv = Crypto.shared.random(count: SecureChannel.blockLength)
        let encrypted = Crypto.shared.aes256Enc(data: plaintextBytes, iv: iv, key: secret)
        let decrypted = Crypto.shared.aes256Dec(data: encrypted, iv: iv, key: secret)

        let decryptedText = String(data: Data(decrypted), encoding: .utf8)
        XCTAssertEqual(decryptedText, plaintext)
    }

    func test_pbkdf() {
        let password = "123456"
        let salt = [UInt8]("Keycard Pairing Password Salt".utf8)
        let hmac = PBKDF2HMac.sha256
        let iterations = 100
        let old = Crypto.shared.new_pbkdf2(password: password, salt: salt, iterations: iterations, hmac: hmac)
        let new = Crypto.shared.pbkdf2(password: password, salt: salt, iterations: iterations, hmac: hmac)
        XCTAssertEqual(new, old)
    }

    func test_cmac() {
        continueAfterFailure = false
        let plaintext = "Hello, World!"
        let plaintextBytes = [UInt8](plaintext.utf8)
        let (sk, pk) = Crypto.shared.secp256k1GeneratePair()
        let secret = Crypto.shared.secp256k1ECDH(privKey: sk, pubKey: pk)
        let fullKey = Crypto.shared.sha512(secret)
        XCTAssertEqual(fullKey.count, 64)
        let macKey = Array(fullKey[48...])
        XCTAssertEqual(macKey.count, 16)
        let data = Crypto.shared.aes256CMac(data: plaintextBytes, key: macKey)
        XCTAssertFalse(data.isEmpty)
    }

}
