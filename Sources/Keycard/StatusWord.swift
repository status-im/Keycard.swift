public enum StatusWord: UInt16, Error {
    case ok = 0x9000
    case securityConditionNotSatisfied = 0x6982
    case authenticationMethodBlocked = 0x6983
    case cardLocked = 0x6283
    case referencedDataNotFound = 0x6A88
    case conditionsOfUseNotSatisfied = 0x6985
    case wrongPINMask = 0x63C0
    case unknownError = 0x6F00
    case pairingIndexInvalid = 0x6A86
    case dataInvalid = 0x6A80
    case allPairingSlotsTaken = 0x6A84
    case alreadyInitialized = 0x6D00

}
