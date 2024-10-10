/*
 * Copyright 2019 PilzAdam
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

"use strict";

/*
 * Backgound script that holds the common data structures and state used
 * throughout all other scripts.
 *
 * Access from non-background scripts via
 * (await browser.runtime.getBackgroundPage()).getCW()
 * or
 * browser.runtime.getBackgroundPage().then((bg) => {
 * const CW = bg.getCW();
 *
 * //script content
 *
 * });
 */

const CW = {};
// access for non-background scripts
function getCW() {
	return CW;
}

/*
 * Settings
 */

const SETTING_KEY = "certificate_watch:settings";
let settings = {};

// initialize settings
browser.storage.local.get(SETTING_KEY).then((result) => {
	const stored = result[SETTING_KEY];
	if (stored) {
		settings = stored;
	}
});

// helper function
function storeSettings() {
	browser.storage.local.set({[SETTING_KEY]: settings});
}


CW.getSetting = (key, dflt) => {
	if (key in settings) {
		return settings[key];
	} else {
		return dflt;
	}
};

CW.setSetting = (key, value) => {
	// copy any arrays or objects to not have references to dead objects
	// shallow copy should be enough...
	if (typeof value === "object") {
		if (Array.isArray(value)) {
			value = [...value];
		} else {
			value = Object.assign({}, value);
		}
	}

	settings[key] = value;
	storeSettings();
};

CW.deleteSetting = (key) => {
	delete settings[key];
	storeSettings();
};

/*
 * Migrate old settings key
 */
function migrateOldSettings() {
	const oldSettingsKey = "certificate_checker:settings";
	browser.storage.local.get(oldSettingsKey).then(
		(result) => {
			const oldSettings = result[oldSettingsKey];
			if (oldSettings) {
				// we found old settings, delete and store as new one
				browser.storage.local.set({[SETTING_KEY]: oldSettings});
				browser.storage.local.remove(oldSettingsKey);
				settings = oldSettings;
				CW.logInfo("Migrated old storage");
			}
		}
	);
}
migrateOldSettings();

/*
 * En-/disabled
 */

CW.enabled = true;

CW.toggleEnabled = () => {
	CW.enabled = !CW.enabled;

	if (CW.enabled === false) {
		CW.logInfo("Disabled functionality (temporary)");
	} else {
		CW.logInfo("Enabled functionality");
	}

	// clear all tabs and update all icons
	for (const tabId of Object.keys(CW.tabs)) {
		const tab = CW.tabs[tabId];
		tab.clear();
		CW.updateTabIcon(tab.tabId);
	}
};

/*
 * Certficate status
 */

CW.CertStatus = class {
	//text;
	//precedence;
	//icon;

	constructor(text, precedence, icon) {
		this.text = text;
		this.precedence = precedence;
		this.icon = icon;
	}
};

CW.CERT_ERROR = new CW.CertStatus(browser.i18n.getMessage("tooltipCertError"), 4, "icons/cw_16_error.png");
CW.CERT_CHANGED = new CW.CertStatus(browser.i18n.getMessage("tooltipCertChanged"), 3, "icons/cw_16_changed.png");
CW.CERT_TOFU = new CW.CertStatus(browser.i18n.getMessage("tooltipCertTofu"), 2, "icons/cw_16_tofu.png");
CW.CERT_STORED = new CW.CertStatus(browser.i18n.getMessage("tooltipCertStored"), 1, "icons/cw_16_stored.png");
CW.CERT_NEW = new CW.CertStatus(browser.i18n.getMessage("tooltipCertChanged"), 1, "icons/cw_16_changed.png");
CW.CERT_NONE = new CW.CertStatus(browser.i18n.getMessage("tooltipCertNone"), 0, "icons/cw_16.png");


CW.CheckResult = class {
	//host;
	//status = CW.CERT_ERROR;
	//if (status === CW.CERT_CHANGED)
	//    changes = {
	//        [key]: {stored: "", got: ""}
	//    };
	//    stored = <CW.Certificate>;
	//    got = <CW.Certificate>;
	//    accepted = <bool>;

	constructor(host) {
		this.host = host;
		this.status = CW.CERT_ERROR;
	}
};

/*
 * Tabs
 */

CW.Tab = class {
	//tabId;
	//results = [];
	//highestStatus = CW.CERT_NONE;
	//lastState = undefined;

	constructor(tabId) {
		this.tabId = tabId;
		this.results = [];
		this.highestStatus = CW.CERT_NONE;
	}

	static async getActiveTab() {
		const activeTabs = await browser.tabs.query({active: true, currentWindow: true});
		if (activeTabs.length === 0) {
			return;
		}
		const tabId = activeTabs[0].id;
		return CW.getTab(tabId);
	}

	addResult(/*CheckResult*/ result) {
		this.results.push(result);
		if (result.status.precedence > this.highestStatus.precedence) {
			this.highestStatus = result.status;
		}

		browser.runtime.sendMessage({
			type: "tab.newResult",
			tabId: this.tabId,
			resultIndex: this.results.length - 1
		}).then(() => {}, () => {}); // ignore errors
	}

	clear() {
		this.results = [];
		this.highestStatus = CW.CERT_NONE;

		browser.runtime.sendMessage({
			type: "tab.resultsCleared",
			tabId: this.tabId
		}).then(() => {}, () => {}); // ignore errors
	}

};

CW.tabs = {
	// [tabId]: Tab
};

CW.getTab = (tabId) => {
	if (CW.tabs[tabId]) {
		return CW.tabs[tabId];
	} else {
		const tab = new CW.Tab(tabId);
		CW.tabs[tabId] = tab;
		return tab;
	}
};

/*
 * Certificate
 */

const certStore = {
	// [host]: CW.Certificate
};

CW.storageInitialized = false;

// initialize storage
browser.storage.local.get().then(
	(result) => {
		for (const host of Object.keys(result)) {
			if (host === SETTING_KEY) {
				continue;
			}

			const stored = result[host];
			certStore[host] = new CW.Certificate(
				stored.subject,
				stored.issuer,
				stored.validity,
				stored.subjectPublicKeyInfoDigest,
				stored.serialNumber,
				stored.fingerprint,
				stored.lastSeen
			);
		}

		CW.logInfo("Initialized storage");
		CW.storageInitialized = true;
		browser.runtime.sendMessage({
			type: "storage.initialized"
		}).then(() => {}, () => {}); // ignore errors
	},
	(error) => {
		// error case
		CW.logInfo("Could not read storage:", e);
		CW.storageInitialized = true;
	}
);

// helper function
function storeCertificate(host){
	// only actually store certificates when we got the real storage
	if (CW.storageInitialized) {
		browser.storage.local.set({
			[host]: certStore[host]
		});
	}
}


CW.Certificate = class {
	//subject;
	//issuer;
	//validity;
	//subjectPublicKeyInfoDigest;
	//serialNumber;
	//fingerprint;
	//lastSeen; // milliseconds since unix epoch, may be undefined

	constructor(subject, issuer, validity, subjectPublicKeyInfoDigest, serialNumber, fingerprint, lastSeen) {
		this.subject = subject;
		this.issuer = issuer;
		this.validity = validity;
		this.subjectPublicKeyInfoDigest = subjectPublicKeyInfoDigest;
		this.serialNumber = serialNumber;
		this.fingerprint = fingerprint;
		this.lastSeen = lastSeen;
	}

	static fromBrowserCert(browserCert) {
		return new CW.Certificate(
			browserCert.subject,
			browserCert.issuer,
			browserCert.validity,
			browserCert.subjectPublicKeyInfoDigest.sha256,
			browserCert.serialNumber,
			browserCert.fingerprint.sha256,
			Date.now()
		);
	}

	static fromStorage(host) {
		if (host === SETTING_KEY) {
			return;
		}
		return certStore[host];
	}

	// returns {[host]: CW.Certificate}
	// do not write to this
	static getAllFromStorage() {
		const certs = Object.assign({}, certStore);
		delete certs[SETTING_KEY];
		return certs;
	}

	static removeFromStorage(host, sendMessage) {
		if (certStore[host]) {
			delete certStore[host];
			if (CW.storageInitialized) {
				browser.storage.local.remove(host);
			}

			if (sendMessage !== false) {
				browser.runtime.sendMessage({
					type: "storage.removedHost",
					host: host,
					oldCert: certStore[host]
				}).then(() => {}, () => {}); // ignore errors
			}
		}
	}

	seen() {
		this.lastSeen = Date.now();
	}

	store(host) {
		if (host === SETTING_KEY) {
			return;
		}

		certStore[host] = this;
		storeCertificate(host);

		if (!certStore[host]) {
			browser.runtime.sendMessage({
				type: "storage.newHost",
				host: host,
				newCert: this
			}).then(() => {}, () => {}); // ignore errors
		} else {
			browser.runtime.sendMessage({
				type: "storage.certChanged",
				host: host,
				oldCert: certStore[host],
				newCert: this
			}).then(() => {}, () => {}); // ignore errors
		}
	}

	// returns [lowerEstimate, upperEstimate]
	estimateSize() {
		// function for getting the string memory size, assuming UTF-8
		function getStringSizeUTF8(str) {
			return unescape(encodeURIComponent(str)).length;
		}
		function getStringSizeUTF16(str) {
			return str.length * 2;
		}

		let lower = 0;
		lower += getStringSizeUTF8(this.subject);
		lower += getStringSizeUTF8(this.issuer);
		lower += getStringSizeUTF8(this.subjectPublicKeyInfoDigest);
		lower += getStringSizeUTF8(this.serialNumber);
		lower += getStringSizeUTF8(this.fingerprint);
		lower += 8 + 8; // validty start and end
		if (this.lastSeen) {
			lower += 8;
		}

		let upper = 0;
		upper += getStringSizeUTF16(this.subject);
		upper += getStringSizeUTF16(this.issuer);
		upper += getStringSizeUTF16(this.subjectPublicKeyInfoDigest);
		upper += getStringSizeUTF16(this.serialNumber);
		upper += getStringSizeUTF16(this.fingerprint);
		upper += 8 + 8; // validty start and end
		if (this.lastSeen) {
			upper += 8;
		}

		return [lower, upper];
	}

};

/*
 * Logging
 */

CW.logDebug = (...args) => {
	const level = CW.getSetting("logLevel");
	if (level === "debug") {
		args.unshift("[Certificate Watch]", "[Debug]");
		console.log.apply(console, args);
	}
};

CW.logInfo = (...args) => {
	const level = CW.getSetting("logLevel");
	if (level === "debug" || level === "info") {
		args.unshift("[Certificate Watch]", "[Info]");
		console.log.apply(console, args);
	}
};
