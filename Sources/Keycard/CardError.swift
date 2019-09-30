import Foundation

public enum CardError: Error {
    case wrongPIN(retryCounter: Int)
    case unrecoverableSignature
    case invalidState
    case notPaired
    case pinBlocked
    case invalidAuthData
    case invalidMac
    case communicationError
}

extension CardError: Equatable {

    public static func ==(lhs: CardError, rhs: CardError) -> Bool {
        switch (lhs, rhs) {
        case (.wrongPIN(let lattempt), .wrongPIN(let rattempt)): return lattempt == rattempt
        case (.unrecoverableSignature, .unrecoverableSignature),
             (.invalidState, .invalidState),
             (.notPaired, .notPaired),
             (.pinBlocked, .pinBlocked),
             (.invalidAuthData, .invalidAuthData),
             (.invalidMac, .invalidMac),
             (.communicationError, .communicationError):
            return true
        default: return false
        }
    }

}
