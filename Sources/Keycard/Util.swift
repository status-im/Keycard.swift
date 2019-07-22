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
            defer {
                last = nil
            }
            return UInt8(lastHexDigitValue * 16 + hexDigitValue)
        }
    }
}

extension Array {
    func chunked(into size: Int) -> [ArraySlice<Element>] {
        return stride(from: 0, to: count, by: size).map {
            self[$0 ..< Swift.min($0 + size, count)]
        }
    }
}

class Util {
    static let shared = Util()
    
    private init() {}
    
    func dropZeroPrefix(uint8: [UInt8]) -> [UInt8] {
        uint8[0] == 0x00 ? Array(uint8[1...]) : uint8
    }
}
