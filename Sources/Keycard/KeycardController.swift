import Foundation
import CoreNFC

@available(iOS 13.0, *)
open class KeycardController: NSObject {

    /// Whether the device supports the Keycard reading
    public static var isAvailable: Bool {
        return NFCNDEFReaderSession.readingAvailable
    }

    private var session: NFCTagReaderSession!
    private let onConnect: (CardChannel) -> Void
    private let onFailure: (Error) -> Void
    private let alertMessages: AlertMessages

    public typealias AlertMessages = (
        moreThanOneTagFound: String,
        unsupportedTagType: String,
        tagConnectionError: String
    )

    /// User-facing alert messages to show on various events.
    public static let defaultAlertMessages = AlertMessages(
        moreThanOneTagFound: "More than one tag was found. Please present only one tag.",
        unsupportedTagType: "Unsupported Smart Card.",
        tagConnectionError: "Connection error. Please try again."
    )

    /// Creates controller with callbacks for connection and disconnection events for a Keycard
    /// - Parameter onConnect: Called when the app connected to the Keycard
    /// - Parameter onFailure: Called when a reading session failed due to various reasons, including leaving the field
    public init?(alertMessages: AlertMessages = KeycardController.defaultAlertMessages,
                 onConnect: @escaping (CardChannel) -> Void,
                 onFailure: @escaping (Error) -> Void) {
        self.alertMessages = alertMessages
        self.onConnect = onConnect
        self.onFailure = onFailure
        super.init()
        guard let session = NFCTagReaderSession(pollingOption: .iso14443, delegate: self) else {
            return nil
        }
        self.session = session
    }

    /// Starts the session with a preconfigured message for display.
    ///
    /// When any NFC tags are detected, controller checks that it's only single tag detected
    /// otherwise it restarts the polling and notifies user with `moreThanOneTagFound` alert message.
    ///
    /// If the detected tag is not ISO7816 tag, then the session is ended with error (`unsupportedTagType` alert message).
    ///
    /// Next, controller tries to connect to the tag. If connection successful, then the `onConnect` is called
    /// on a background thread with a card channel passed in.
    ///
    /// If the connection to the tag failed, then the session is stopped with the `tagConnectionError` alert message.
    ///
    /// At any point, if the session is ended with error, the `onFailure` is called with the respective error.
    ///
    /// - Parameter alertMessage: message about usage of the NFC card
    public func start(alertMessage: String? = nil) {
        setAlert(alertMessage)
        session.begin()
    }

    /// Stops the session with error icon and message displayed.
    /// - Parameter errorMessage: error message to display
    public func stop(errorMessage: String) {
        session.invalidate(errorMessage: errorMessage)
    }

    /// Stops the session with success icon and optionally updated message displayed.
    /// - Parameter alertMessage: alert message to update
    public func stop(alertMessage: String?) {
        setAlert(alertMessage)
        session.invalidate()
    }

    /// Updates the alert message.
    /// - Parameter alertMessage: alert message to display or nil (no-op)
    public func setAlert(_ alertMessage: String?) {
        if let message = alertMessage {
            session.alertMessage = message
        }
    }

}

@available(iOS 13.0, *)
extension KeycardController: NFCTagReaderSessionDelegate {

    public func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {
        // no-op
    }

    public func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
        onFailure(error)
    }

    public func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        if tags.count > 1 {
            setAlert(alertMessages.moreThanOneTagFound)
            tagRemovalDetect(tags[0])
            return
        }
        guard let first = tags.first, case NFCTag.iso7816(let tag) = first else {
            stop(errorMessage: alertMessages.unsupportedTagType)
            return
        }
        session.connect(to: first) { [weak self] error in
            guard let `self` = self else { return }
            if error != nil {
                self.stop(errorMessage: self.alertMessages.tagConnectionError)
                return
            }
            DispatchQueue.global().async {
                self.onConnect(CoreNFCCardChannel(tag: tag))
            }
        }
    }

    // from Apple's exapmle code
    func tagRemovalDetect(_ tag: NFCTag) {
        // In the tag removal procedure, you connect to the tag and query for
        // its availability. You restart RF polling when the tag becomes
        // unavailable; otherwise, wait for certain period of time and repeat
        // availability checking.
        session.connect(to: tag) { [weak self] error in
            guard let `self` = self else { return }
            guard error == nil && tag.isAvailable else {
                self.session.restartPolling()
                return
            }
            DispatchQueue.global().asyncAfter(deadline: DispatchTime.now() + .milliseconds(500), execute: {
                self.tagRemovalDetect(tag)
            })
        }
    }

}
