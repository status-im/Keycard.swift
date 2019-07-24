class CardDuplicator {
    let secret: [UInt8]
    let cmdSet: KeycardCommandSet
    let delegate: DuplicatorDelegate?
    
    var startedDuplication: Set<[UInt8]>
    var addedEntropy: Set<[UInt8]>
    var finishedDuplication: Set<[UInt8]>
    
    init(cmdSet: KeycardCommandSet, delegate: DuplicatorDelegate?) {
        self.cmdSet = cmdSet
        self.delegate = delegate
        self.secret = Crypto.shared.random(count: 32)
        self.startedDuplication = Set()
        self.addedEntropy = Set()
        self.finishedDuplication = Set()
    }
    
    convenience init(channel: CardChannel) {
        self.init(cmdSet: KeycardCommandSet(cardChannel: channel), delegate: nil)
    }
    
    func selectAndCheck(processed: inout Set<[UInt8]>) throws -> ApplicationInfo {
        let appInfo = try ApplicationInfo(cmdSet.select().checkOK().data)
        
        let (inserted, _) = processed.insert(appInfo.instanceUID)
        
        if !inserted {
            throw CardError.invalidState
        }
        
        return appInfo
    }
    
    func preamble(processed: inout Set<[UInt8]>) throws {
        let appInfo = try selectAndCheck(processed: &processed)
        let pairing = delegate!.getPairing(forApplication: appInfo)
        
        if pairing == nil {
            throw CardError.notPaired
        }
        
        cmdSet.pairing = pairing
        try cmdSet.autoOpenSecureChannel()
        
        let appStatus = try ApplicationStatus(cmdSet.getStatus(info: GetStatusP1.application.rawValue).checkOK().data)
        var remainingAttempts = appStatus.pinRetryCount
        
        while remainingAttempts > 0 {
            do {
                _ = try cmdSet.verifyPIN(pin: delegate!.getPIN(forApplication: appInfo, withRemainingAttempts: remainingAttempts))
            } catch CardError.wrongPIN(let retryCount) {
                remainingAttempts = retryCount
            }
        }
        
        if remainingAttempts <= 0 {
            throw CardError.pinBlocked
        }
    }
    
    func startDuplication(clientCount: UInt8) throws {
        try preamble(processed: &startedDuplication)
        _ = try cmdSet.duplicateKeyStart(entropyCount: clientCount, firstEntropy: self.secret).checkOK()
    }
    
    func exportKey() throws -> [UInt8] {
        try preamble(processed: &finishedDuplication)
        return try cmdSet.duplicateKeyExport().checkOK().data
    }
    
    func importKey(key: [UInt8]) throws -> [UInt8] {
        try preamble(processed: &finishedDuplication)
        return try cmdSet.duplicateKeyImport(key: key).checkOK().data
    }
    
    func addEntropy(clientCount: UInt8) throws {
        _ = try selectAndCheck(processed: &addedEntropy)
        _ = try cmdSet.duplicateKeyAddEntropy(entropy: self.secret).checkOK()
    }
}
