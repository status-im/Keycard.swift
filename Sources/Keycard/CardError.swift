enum CardError: Error {
    case wrongPIN(retryCounter: Int)
    case unrecoverableSignature
    case invalidState
    case notPaired
    case pinBlocked
    case invalidAuthData
    case invalidMac
    case communicationError
}
