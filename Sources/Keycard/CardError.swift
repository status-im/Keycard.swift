enum CardError: Error {
    case wrongPIN(retryCounter: Int)
    case unrecoverableSignature
}
