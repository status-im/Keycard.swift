protocol DuplicatorDelegate {
    func getPairing(forApplication applicationInfo: ApplicationInfo) -> Pairing?
    func getPIN(forApplication applicationInfo: ApplicationInfo, withRemainingAttempts remainingAttempts: Int) -> String

}
