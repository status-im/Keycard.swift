import Foundation
import Zip

struct FileLoader {
    private static let blockSize = 247 // 255 - 8 bytes for MAC
    private static let fileNames = ["Header.cap", "Directory.cap", "Import.cap", "Applet.cap", "Class.cap", "Method.cap", "StaticField.cap", "Export.cap", "ConstantPool.cap", "RefLocation.cap"]
    private static let fileTag: UInt8 = 0xc4

    public enum Error: Swift.Error {
        case fileIsTooLarge
    }

    private var currentBlock: UInt8 = 0
    private var dataOffset: Int = 0
    private var data: [UInt8]

    public init(fileURL: URL) throws {
        let files = Self.unzipFileAndGetSubfilesURLs(fileURL: fileURL)

        // Flatten the data contained in each file
        let flattenedFileData = files.flatMap { Array(try! Data(contentsOf: $0)) }
        let encodedLength = try Self.encodeFullLength(flattenedFileData.count)
        self.data = [Self.fileTag] + encodedLength + flattenedFileData
    }

    private static func unzipFileAndGetSubfilesURLs(fileURL: URL) -> [URL] {
        Zip.addCustomFileExtension("cap")
        let unzipDirectory = try! Zip.quickUnzipFile(fileURL)
        var files = [URL](repeating: unzipDirectory, count: fileNames.count)
        if let enumerator = FileManager.default.enumerator(at: unzipDirectory, includingPropertiesForKeys: [.isRegularFileKey], options: [.skipsHiddenFiles, .skipsPackageDescendants]) {
            for case let fileURL as URL in enumerator {
                if let fileIndex = fileNames.firstIndex(of: fileURL.pathComponents.last ?? "") {
                    // Add the files to their appropriate location (order)
                    files[fileIndex] = fileURL
                }
            }
            // Remove files that were not presen in the CAP file
            files = files.filter { $0 != unzipDirectory }
        }
        return files
    }

    private static func encodeFullLength(_ length: Int) throws -> [UInt8] {
        if length < 0x80 {
            return [UInt8(length)]
        } else if length < 0xff {
            return [0x81, UInt8(length)]
        } else if length < 0xffff {
            return [0x82, UInt8((length & 0xff00) >> 8), UInt8(length & 0xff)]
        } else if length <= 0xffffff {
            return [0x83, UInt8((length & 0xff0000) >> 16), UInt8((length & 0xff00) >> 8), UInt8(length & 0xff)]
        } else {
            throw Error.fileIsTooLarge
        }
    }
}

extension FileLoader: Sequence, IteratorProtocol {

    struct Element {
        var data: [UInt8]
        var blockCount: UInt8
        var hasMoreBlocks: Bool
    }

    var underestimatedCount: Int { (data.count / Self.blockSize) + ((data.count % Self.blockSize) > 0 ? 1 : 0) }

    mutating func next() -> Element? {
        guard currentBlock < underestimatedCount else { return nil }
        defer {
            currentBlock += 1
            dataOffset = dataOffset + Self.blockSize
        }
        return Element(
            data: Array(data[dataOffset ..< Swift.min(dataOffset + Self.blockSize, data.count)]),
            blockCount: currentBlock,
            hasMoreBlocks: currentBlock == (underestimatedCount - 1)
        )
    }
}
