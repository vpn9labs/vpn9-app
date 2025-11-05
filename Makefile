APP_BUNDLE := target/release/bundle/macos/vpn9-app.app
DAEMON_BIN := target/release/vpn9-daemon
BUILD_DIR := build
PKGROOT := $(BUILD_DIR)/package-root
SCRIPTS_DIR := $(BUILD_DIR)/scripts
PKG_OUTPUT_DIR := $(BUILD_DIR)/pkg
COMPONENT_PLIST := $(BUILD_DIR)/component.plist
PKG_IDENTIFIER := com.vpn9.pkg
PKG_NAME := VPN9-Installer
VERSION := $(shell grep -m1 '^version = ' Cargo.toml | sed 's/.*"\(.*\)".*/\1/')
PKG_PATH := $(PKG_OUTPUT_DIR)/$(PKG_NAME)-$(VERSION).pkg
APP_SIGNING_IDENTITY ?=
INSTALLER_SIGNING_IDENTITY ?=

ifeq ($(strip $(VERSION)),)
$(error Unable to determine version from Cargo.toml)
endif

.PHONY: all help tauri-app daemon stage prepare-scripts component-plist package clean codesign-app codesign-daemon codesign-pkg notarize

all: package

help:
	@echo "Available targets:"
	@echo "  tauri-app      Build the Tauri macOS app bundle"
	@echo "  daemon         Build the vpn9-daemon binary"
	@echo "  stage          Stage app, daemon, and plist into pkgroot"
	@echo "  package        Build the unsigned macOS installer pkg at $(PKG_PATH)"
	@echo "  codesign-app   Codesign the staged app bundle (requires APP_SIGNING_IDENTITY)"
	@echo "  codesign-daemon Codesign the staged daemon binary (requires APP_SIGNING_IDENTITY)"
	@echo "  codesign-pkg   Codesign the generated pkg (requires INSTALLER_SIGNING_IDENTITY)"
	@echo "  notarize       Submit the pkg for notarization (requires NOTARY_PROFILE)"
	@echo "  clean          Remove staging directories"

tauri-app:
	cargo tauri build --bundles app

daemon:
	cargo build -p vpn9-daemon --release

prepare-scripts:
	rm -rf $(SCRIPTS_DIR)
	mkdir -p $(SCRIPTS_DIR)
	cp packaging/macos/scripts/preinstall $(SCRIPTS_DIR)/preinstall
	cp packaging/macos/scripts/postinstall $(SCRIPTS_DIR)/postinstall
	chmod +x $(SCRIPTS_DIR)/preinstall $(SCRIPTS_DIR)/postinstall

stage: tauri-app daemon
	@test -d $(APP_BUNDLE) || (echo "error: app bundle not found at $(APP_BUNDLE)" && exit 1)
	@test -x $(DAEMON_BIN) || (echo "error: daemon binary not found at $(DAEMON_BIN)" && exit 1)
	rm -rf $(PKGROOT)
	mkdir -p $(PKGROOT)/Applications
	ditto $(APP_BUNDLE) $(PKGROOT)/Applications/VPN9.app
	mkdir -p $(PKGROOT)/usr/local/libexec/vpn9
	install -m 755 $(DAEMON_BIN) $(PKGROOT)/usr/local/libexec/vpn9/vpn9-daemon
	mkdir -p $(PKGROOT)/Library/LaunchDaemons
	install -m 644 packaging/macos/com.vpn9.daemon.plist $(PKGROOT)/Library/LaunchDaemons/com.vpn9.daemon.plist

component-plist: stage
	pkgbuild --analyze --root $(PKGROOT) $(COMPONENT_PLIST)
	/usr/libexec/PlistBuddy -c "Set :0:BundleIsRelocatable false" $(COMPONENT_PLIST) || \
	  /usr/libexec/PlistBuddy -c "Add :0:BundleIsRelocatable bool false" $(COMPONENT_PLIST)
	/usr/libexec/PlistBuddy -c "Set :0:BundleInstallPath /Applications" $(COMPONENT_PLIST) || \
	  /usr/libexec/PlistBuddy -c "Add :0:BundleInstallPath string /Applications" $(COMPONENT_PLIST)

package: component-plist prepare-scripts
	mkdir -p $(PKG_OUTPUT_DIR)
	pkgbuild --root $(PKGROOT) \
	  --identifier $(PKG_IDENTIFIER) \
	  --version $(VERSION) \
	  --scripts $(SCRIPTS_DIR) \
	  --component-plist $(COMPONENT_PLIST) \
	  $(PKG_PATH)

codesign-app: stage
ifndef APP_SIGNING_IDENTITY
	$(error APP_SIGNING_IDENTITY must be set, e.g. make APP_SIGNING_IDENTITY="Developer ID Application: Example" codesign-app)
endif
	codesign --force --deep --options runtime --sign "$(APP_SIGNING_IDENTITY)" $(PKGROOT)/Applications/VPN9.app

codesign-daemon: stage
ifndef APP_SIGNING_IDENTITY
	$(error APP_SIGNING_IDENTITY must be set, e.g. make APP_SIGNING_IDENTITY="Developer ID Application: Example" codesign-daemon)
endif
	codesign --force --options runtime --sign "$(APP_SIGNING_IDENTITY)" $(PKGROOT)/usr/local/libexec/vpn9/vpn9-daemon

codesign-pkg: package
ifndef INSTALLER_SIGNING_IDENTITY
	$(error INSTALLER_SIGNING_IDENTITY must be set, e.g. make INSTALLER_SIGNING_IDENTITY="Developer ID Installer: Example" codesign-pkg)
endif
	codesign --force --sign "$(INSTALLER_SIGNING_IDENTITY)" $(PKG_PATH)

notarize: package
ifndef NOTARY_PROFILE
	$(error NOTARY_PROFILE must be set to an xcrun notarytool keychain profile name)
endif
	xcrun notarytool submit $(PKG_PATH) --keychain-profile "$(NOTARY_PROFILE)" --wait
	xcrun stapler staple $(PKG_PATH)

clean:
	rm -rf $(PKGROOT) $(SCRIPTS_DIR) $(PKG_OUTPUT_DIR) $(COMPONENT_PLIST)
