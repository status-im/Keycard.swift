import XCTest
@testable import Keycard

final class CryptoTests: XCTestCase {

    func test_encrypt_decrypt() {
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

}
