enum CLA: UInt8 {
    case iso7816 = 0x00
    case proprietary = 0x80
}

enum ISO7816INS: UInt8 {
    case select = 0xa4
}

enum KeycardINS: UInt8 {
    case initialize = 0xfe
    case getStatus = 0xf2
    case verifyPIN = 0x20
    case changePIN = 0x21
    case unblockPIN = 0x22
    case loadKey = 0xd0
    case deriveKey = 0xd1
    case generateMnemonic = 0xd2
    case removeKey = 0xd3
    case generateKey = 0xd4
    case sign = 0xc0
    case setPinlessPath = 0xc1
    case exportKey = 0xc2
    case getData = 0xca
    case storeData = 0xe2
}

public enum ChangePINP1: UInt8 {
    case userPIN = 0x00
    case puk = 0x01
    case pairingSecret = 0x02
}

public enum GetStatusP1: UInt8 {
    case application = 0x00
    case keyPath = 0x01
}

public enum LoadKeyP1: UInt8 {
    case ec = 0x01
    case extEC = 0x02
    case seed = 0x03
}

public enum DeriveKeyP1: UInt8 {
    case fromMaster = 0x00
    case fromParent = 0x40
    case fromCurrent = 0x80
}

public enum DuplicateKeyP1: UInt8 {
    case start = 0x00
    case addEntropy = 0x01
    case exportKey = 0x02
    case importKey = 0x03
}

public enum GenerateMnemonicP1: UInt8 {
    case length12Words = 0x04
    case length15Words = 0x05
    case length18Words = 0x06
    case length21Words = 0x07
    case length24Words = 0x08
}

public enum SignP1: UInt8 {
    case currentKey = 0x00
    case deriveKey = 0x01
    case deriveAndMakeCurrent = 0x02
    case pinless = 0x03
}

public enum ExportKeyP1: UInt8 {
    case currentKey = 0x00
    case deriveKey = 0x01
    case deriveAndMakeCurrent = 0x02
}

public enum ExportKeyP2: UInt8 {
    case privateAndPublic = 0x00
    case publicOnly = 0x01
}

enum SecureChannelINS: UInt8 {
    case openSecureChannel = 0x10
    case mutuallyAuthenticate = 0x11
    case pair = 0x12
    case unpair = 0x13
}

public enum PairP1: UInt8 {
    case firstStep = 0x00
    case lastStep = 0x01
}

public enum StoreDataP1: UInt8 {
    case publicData = 0x00
    case ndef = 0x01
    case cash = 0x02
}

public enum Identifier: String {
    case packageAID = "A0000008040001"
    case keycardAID = "A000000804000101"
    case ndefAID = "A000000804000102"
    case ndefInstanceAID = "D2760000850101"
    case keycardCashAID = "A000000804000103"
    case keycardCashInstanceAID = "A00000080400010301"

    public var val: [UInt8] {
        return rawValue.hexToBytes
    }

    public static func getKeycardInstanceAID(instanceId: UInt8 = 1) -> [UInt8] {
        precondition(instanceId >= 1, "The instance index must be between 1 and 255")
        return keycardAID.val + [instanceId]
    }
}
