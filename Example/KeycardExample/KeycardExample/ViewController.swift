//
//  ViewController.swift
//  KeycardExample
//
//  Created by Dmitry Bespalov on 03.09.19.
//  Copyright © 2019 Gnosis Ltd. All rights reserved.
//

import UIKit
import CoreNFC
import Keycard
import CryptoSwift
import os
import CommonCrypto

class TableViewController: UITableViewController {

    var actions: [Action] = []
    var nfcController: NFCController!

    override func viewDidLoad() {
        super.viewDidLoad()

        actions = [
            Action(name: "Get Status", closure: getStatus),
            Action(name: "Initialize", closure: initialize),
            Action(name: "PBKDF2", closure: pbkdf)
        ]

        DispatchQueue.main.async {
            if !NFCController.isAvailable {
                let alertController = UIAlertController(
                    title: "Scanning Not Supported",
                    message: "This device doesn't support tag scanning. The functionality is disabled.",
                    preferredStyle: .alert
                )
                alertController.addAction(UIAlertAction(title: "OK", style: .default, handler: nil))
                self.present(alertController, animated: true, completion: nil)
            }
        }
    }

    override func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        return actions.count
    }

    override func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = tableView.dequeueReusableCell(withIdentifier: "Action", for: indexPath)
        let action = actions[indexPath.row]
        cell.textLabel?.text = action.name
        cell.accessoryType = .disclosureIndicator
        return cell
    }

    override func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        tableView.deselectRow(at: indexPath, animated: true)
        let action = actions[indexPath.row]
        action.closure()
    }

    func getStatus() {
        guard nfcController == nil else { return }
        nfcController = NFCController(message: "Hold your iPhone near a Status Keycard.")
        nfcController.start(execute: { [unowned self] tag in
            do {
                let channel = CoreNFCCardChannel(tag: tag)
                let cmdSet = KeycardCommandSet(cardChannel: channel)
                let info = try ApplicationInfo(cmdSet.select().checkOK().data)
                let status = """
                initialized: \(info.initializedCard ? "YES" : "NO")
                instanceUID: \(Data(info.instanceUID).toHexString())
                appVersion:  \(info.appVersionString)
                freeSlots: \(info.freePairingSlots)
                hasMasterKey: \(info.hasMasterKey ? "YES" : "NO")
                keyUID: \(info.keyUID)
                """
                tag.session?.alertMessage = "Success"
                tag.session?.invalidate()
                self.present(string: status)
            } catch {
                tag.session?.invalidate(errorMessage: "Read error. Please try again.")
                self.present(string: "Error: \(error)")
            }
            self.nfcController = nil
        }, failure: { _ in
            self.nfcController = nil
        })
    }

    func initialize() {
        guard nfcController == nil else { return }

        let initializeAction: (String, String, String) -> Void = { [unowned self] pin, puk, pass in
            self.nfcController = NFCController(message: "Hold your iPhone near a Status Keycard.")
            self.nfcController.start(execute: { [unowned self] tag in
                tag.session?.alertMessage = "Initializatng... Please do not remove the Keycard."
                do {
                    let channel = CoreNFCCardChannel(tag: tag)
                    let cmdSet = KeycardCommandSet(cardChannel: channel)
                    try cmdSet.select().checkOK()
                    try cmdSet.initialize(pin: pin, puk: puk, pairingPassword: pass).checkOK()
                    tag.session?.alertMessage = "Success"
                    tag.session?.invalidate()
                } catch {
                    tag.session?.invalidate(errorMessage: "Read error. Please try again.")
                    self.present(string: "Error: \(error)")
                }
                self.nfcController = nil
            }, failure: { _ in
                self.nfcController = nil
            })
        }

        let inputAlert = UIAlertController(
            title: "Input",
            message: "Please enter required information",
            preferredStyle: .alert)
        inputAlert.addTextField { field in
            field.placeholder = "PIN (6 digits)"
            field.keyboardType = .numberPad
        }
        inputAlert.addTextField { field in
            field.placeholder = "PUK (12 digits)"
            field.keyboardType = .numberPad
        }
        inputAlert.addTextField { field in
            field.placeholder = "Pairing Password"
        }
        inputAlert.addAction(UIAlertAction(title: "Initialize", style: .default, handler: { [unowned inputAlert] action in
            guard let pin = inputAlert.textFields?[0].text,
                let puk = inputAlert.textFields?[1].text,
                let pass = inputAlert.textFields?[2].text else {
                    return
            }
            let memo = """
            PIN: \(pin)
            PUK: \(puk)
            Pairing Password: \(pass)
            """
            UIPasteboard.general.string = memo
            initializeAction(pin, puk, pass)
        }))
        inputAlert.addAction(UIAlertAction(title: "Cancel", style: .cancel, handler: nil))
        self.present(inputAlert, animated: true, completion: nil)

    }

    func present(string: String) {
        if !Thread.isMainThread {
            DispatchQueue.main.async { self.present(string: string) }
            return
        }
        let alertController = UIAlertController(
            title: "Result",
            message: string,
            preferredStyle: .alert
        )
        alertController.addAction(UIAlertAction(title: "OK", style: .default, handler: nil))
        self.present(alertController, animated: true, completion: nil)
    }

    func pbkdf() {

        DispatchQueue.global().async {
            // 50 000 - 29, 29, 29
            // 25 000 - 14, 14
            // 15 000 - 9
            // 10 000 - 6 seconds!
//            os_log("start")
//            self.pbkdf2(password: "qwe123qwe", salt: Array("Keycard Pairing Password Salt".utf8), iterations: 10000, hmac: .sha256)
//            os_log("end")

            os_log("start")
            self.systemPBKDF(password: "qwe123qwe", salt: Array("Keycard Pairing Password Salt".utf8))
            os_log("end")
        }
    }

    func systemPBKDF(password: String, salt: [UInt8]) {
        assert(salt.count < 133)
        let passwordBytes = [UInt8](password.utf8)
        let iterations = CCCalibratePBKDF(CCPBKDFAlgorithm(kCCPBKDF2),
                                          passwordBytes.count,
                                          salt.count,
                                          CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                                          256 / 8,
                                          500)
        print("iterations: \(iterations)")
        if iterations == .max {
            print("PBKDF calibration error!")
            return
        }

        var saltBytes = salt
        var bytesInt8 = passwordBytes.map { Int8(exactly: $0)! }

        var key: [UInt8] = []

        let result = CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2),
                                          &bytesInt8,
                                          bytesInt8.count,
                                          &saltBytes,
                                          saltBytes.count,
                                          CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                                          iterations,
                                          &key,
                                          256 / 8)
        if result == kCCParamError {
            print("PBKDF error")
        }
    }

    enum PBKDF2HMac {
        case sha256
        case sha512
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
}

struct Action {
    var name: String
    var closure: () -> Void
}

class NFCController: NSObject, NFCTagReaderSessionDelegate {

    static var isAvailable: Bool {
        return NFCNDEFReaderSession.readingAvailable
    }

    let message: String
    var session: NFCTagReaderSession!
    var execute: ((NFCISO7816Tag) -> Void)!
    var failure: ((Error) -> Void)!

    init(message: String) {
        self.message = message
    }

    func start(execute: @escaping (NFCISO7816Tag) -> Void, failure: @escaping (Error) -> Void) {
        guard NFCController.isAvailable else { return }
        self.execute = execute
        self.failure = failure
        session = NFCTagReaderSession(pollingOption: .iso14443, delegate: self)
        session.alertMessage = message
        session.begin()
    }

    // MARK: - NFCTagReaderSessionDelegate

    func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {
        // no-op
    }

    func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
        failure?(error)
    }

    func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        if tags.count > 1 {
            session.alertMessage = "More than one tag was found. Please present only one tag."
            tagRemovalDetect(tags[0])
            return
        }
        guard let first = tags.first, case NFCTag.iso7816(let tag) = first else {
            session.invalidate(errorMessage: "Unsupported Smart Card.")
            return
        }
        session.connect(to: first) { [weak self] error in
            if let error = error {
                print("Connection error: \(error)")
                session.invalidate(errorMessage: "Connection error. Please try again.")
                return
            }
            DispatchQueue.global().async {
                self?.execute?(tag)
            }
        }
    }

    func tagRemovalDetect(_ tag: NFCTag) {
        // In the tag removal procedure, you connect to the tag and query for
        // its availability. You restart RF polling when the tag becomes
        // unavailable; otherwise, wait for certain period of time and repeat
        // availability checking.
        self.session?.connect(to: tag) { [weak self] error in
            guard let `self` = self else { return }
            guard error == nil && tag.isAvailable else {
                self.session?.restartPolling()
                return
            }
            DispatchQueue.global().asyncAfter(deadline: DispatchTime.now() + .milliseconds(500), execute: {
                self.tagRemovalDetect(tag)
            })
        }
    }

}
