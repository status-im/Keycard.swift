enum TLVTag: UInt8 {
    case int = 0x01
    case bool = 0x02
}

enum TLVError: Error {
    case unexpectedTag(expected: UInt8, actual: UInt8)
    case unexpectedLength(length: Int)
    case endOfTLV
}

class TinyBERTLV {
    let buf: [UInt8]
    var pos: Int

    init(_ buf: [UInt8]) {
        self.buf = buf
        self.pos = 0
    }

    func enterConstructed(tag: UInt8) throws -> Int {
        try checkTag(expected: tag, actual: readTag())
        return readLength()
    }

    func readPrimitive(tag: UInt8) throws -> [UInt8] {
        try checkTag(expected: tag, actual: readTag())
        let len = readLength()
        pos += len
        return Array(buf[Int((pos - len))..<pos])
    }

    func readBoolean() throws -> Bool {
        let val = try readPrimitive(tag: TLVTag.bool.rawValue)
        return val[0] == 0xff
    }

    func readInt() throws -> Int {
        let val = try readPrimitive(tag: TLVTag.int.rawValue)
        switch val.count {
        case 1:
            return Int(val[0])
        case 2:
            return (Int(val[0]) << 8) | Int(val[1])
        case 3:
            return (Int(val[0]) << 16) | (Int(val[1] << 8)) | Int(val[2])
        case 4:
            return (Int(val[0]) << 24) | (Int(val[1] << 16)) | (Int(val[2] << 8)) | Int(val[3])
        default:
            throw TLVError.unexpectedLength(length: val.count)
        }
    }

    func readLength() -> Int {
        var len = Int(buf[pos])
        pos += 1

        if (len == 0x81) {
            len = Int(buf[pos])
            pos += 1
        }

        return len
    }

    func readTag() throws -> UInt8 {
        if (pos < buf.count) {
            let ret = buf[pos]
            pos += 1
            return ret
        } else {
            throw TLVError.endOfTLV
        }
    }

    func unreadLastTag() {
        if (pos < buf.count) {
            pos -= 1;
        }
    }

    func checkTag(expected: UInt8, actual: UInt8) throws {
        if (expected != actual) {
            unreadLastTag()
            throw TLVError.unexpectedTag(expected: expected, actual: actual)
        }
    }
}
