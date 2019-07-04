enum CardError : Error {
    case wrongPIN(retryCounter: Int)
}
