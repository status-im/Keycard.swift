import XCTest

#if !canImport(ObjectiveC)
public func allTests() -> [XCTestCaseEntry] {
    return [
        testCase(Keycard_swiftTests.allTests),
    ]
}
#endif
