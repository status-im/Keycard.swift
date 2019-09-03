//
//  KeycardExampleTests.swift
//  KeycardExampleTests
//
//  Created by Dmitry Bespalov on 03.09.19.
//  Copyright © 2019 Gnosis Ltd. All rights reserved.
//

import XCTest
import Keycard
import CryptoSwift

class KeycardExampleTests: XCTestCase {

    override func setUp() {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testExample() {
        // This is an example of a functional test case.
        // Use XCTAssert and related functions to verify your tests produce the correct results.
    }

    func testPerformanceExample() {
        // This is an example of a performance test case.
        measure {
            pbkdf2(password: password, salt: Array("Keycard Pairing Password Salt".utf8), iterations: cardChannel.pairingPasswordPBKDF2IterationCount, hmac: PBKDF2HMac.sha256)
        }
    }


}
