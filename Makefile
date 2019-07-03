.PHONY: documentation test link xcode linuxmain

test:
	swift test

lint:
	swiftlint

documentation:
	jazzy --author "Status" --author_url https://status.im  --github_url https://github.com/status-im/Keycard.swift
	rm -rf build/

xcode:
	swift package generate-xcodeproj

linuxmain:
	swift test --generate-linuxmain
