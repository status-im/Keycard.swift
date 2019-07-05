extension Collection where Element == Character {
    var hexToBytes: [UInt8] {
        var last = first
        return dropFirst().compactMap {
            guard
                let lastHexDigitValue = last?.hexDigitValue,
                let hexDigitValue = $0.hexDigitValue else {
                    last = $0
                    return nil
            }
            defer { last = nil }
            return UInt8(lastHexDigitValue * 16 + hexDigitValue)
        }
    }
}
