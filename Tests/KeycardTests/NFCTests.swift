import Foundation
import XCTest
import CoreNFC
@testable import Keycard

@available(iOS 13.0, *)
final class NFCTests: XCTestCase {

    func test_serialization() {
        let cmd = APDUCommand(cla: CLA.iso7816.rawValue, ins: ISO7816INS.select.rawValue, p1: 0x04, p2: 0x00, data: Identifier.getKeycardInstanceAID())
        guard let apdu = NFCISO7816APDU(data: Data(cmd.serialize())) else {
            XCTFail()
            return
        }

        XCTAssertEqual(apdu.instructionClass, cmd.cla)
        XCTAssertEqual(apdu.instructionCode, cmd.ins)
        XCTAssertEqual(apdu.p1Parameter, cmd.p1)
        XCTAssertEqual(apdu.p2Parameter, cmd.p2)
        XCTAssertEqual(apdu.data, Data(cmd.data))
    }

}
