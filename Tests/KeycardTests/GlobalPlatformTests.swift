import XCTest
@testable import Keycard

final class GlobalPlatformTests: XCTestCase {
    func testSCP02() {
        let scp02 = SCP02(channel: TestCardChannel())
        let hostChallenge = Crypto.shared.random(count: 8)
        var cardChallenge = Crypto.shared.random(count: 8)
        cardChallenge[0] = 0x00
        cardChallenge[1] = 0x0f
        
        var cardData = [UInt8](repeating: 0, count: 12)
        cardData.append(contentsOf: cardChallenge)
        
        let encKey = scp02.deriveSessionKey(key: GlobalPlatformKeys.statusKeys.val, seq: [0x00, 0x0f], purpose: SCP02.derivationPurposeEnc)
        scp02.encKey = encKey
        cardData.append(contentsOf: scp02.generateCryptogram(challenge1: hostChallenge, challenge2: cardChallenge))
        
        XCTAssertTrue(scp02.verifyChallenge(hostChallenge: hostChallenge, key: GlobalPlatformKeys.statusKeys.val, cardResponse: cardData))
        XCTAssertFalse(scp02.verifyChallenge(hostChallenge: hostChallenge, key: GlobalPlatformKeys.defaultKeys.val, cardResponse: cardData))
    }
}
