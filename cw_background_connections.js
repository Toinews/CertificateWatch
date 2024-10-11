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
/* global CW */

/*
 * Background script that intercepts and checks all TLS connections.
 */

function isDomainInList(host, domainsList) {
	const hostParts = host.split(".");
	for (let filter of domainsList) {
		filter = filter.trim();
		if (filter.length > 0) {
			const filterParts = filter.split(".");
			if (filterParts.length === hostParts.length) {
				let match = true;
				for (let i = 0; i < filterParts.length; i++) {
					if (filterParts[i] !== "*" && filterParts[i] !== hostParts[i]) {
						match = false;
						break;
					}
				}

				if (match) {
					CW.logDebug("Ignoring domain", host, "because it matches", filter);
					return true;
				}
			}
		}
	}

	return false;
}

function analyzeCert(host, securityInfo, result) {
	const strictMode = CW.getSetting("strictMode", true);
	if (!securityInfo.certificates || securityInfo.certificates.length !== 1) {
		result.status = CW.CERT_ERROR;
		return;
	}

	const cert = CW.Certificate.fromBrowserCert(securityInfo.certificates[0]);
	const storedCert = CW.Certificate.fromStorage(host);

	if (!storedCert) {
			result.status = CW.CERT_TOFU;
		if (!strictMode) {
			cert.store(host);
		} else {
			result.got = cert;
			result.accepted = false;
			result.changes = {};
			result.stored = {
				"subject": "NEW",
				"issuer": "NEW",
				"validity": "NEW",
				"subjectPublicKeyInfoDigest": "NEW",
				"serialNumber": "0",
				"fingerprint": "0"
			}
			result.changes["subject"] = {stored: "NEW", got: cert["subject"]}
			result.changes["issuer"] = {stored: "NEW", got: cert["issuer"]}
			result.changes["validity"] = {stored: { "start": 0, "end": 0}, got: cert["validity"]}
			result.changes["subjectPublicKeyInfoDigest"] = {stored: "NEW", got: cert["subjectPublicKeyInfoDigest"]}
			result.changes["serialNumber"] = {stored: "0", got: cert["serialNumber"]}
			result.changes["fingerprint"] = {stored: "0", got: cert["fingerprint"]}
		}
	} else {
		if (storedCert.rejected === true) 
		{
			result.status = CW.CERT_REJECTED;
			return;
		}
		const changes = {};
		const checkedFields = CW.getSetting("checkedFields",
				["subject", "issuer", "validity", "subjectPublicKeyInfoDigest", "serialNumber", "fingerprint"]);
		let checkedFieldChanged = false;
		// fields are roughly sorted by importance
		for (const field of ["subject", "issuer", "validity", "subjectPublicKeyInfoDigest", "serialNumber", "fingerprint"]) {
			if (field === "validity") {
				// validity needs extra comparison logic
				if (cert.validity.start !== storedCert.validity.start ||
						cert.validity.end !== storedCert.validity.end) {
					changes.validity = {
						stored: {start: storedCert.validity.start, end: storedCert.validity.end},
						got: {start: cert.validity.start, end: cert.validity.end}
					};
					if (checkedFields.includes(field)) {
						checkedFieldChanged = true;
					}
				}
			} else {
				if (cert[field] !== storedCert[field]) {
					changes[field] = {
						stored: storedCert[field],
						got: cert[field]
					};
					if (checkedFields.includes(field)) {
						checkedFieldChanged = true;
					}
				}
			}
		}

		if (Object.keys(changes).length > 0) {
			if (checkedFieldChanged) {
				result.status = CW.CERT_CHANGED;
				result.changes = changes;
				result.stored = storedCert;
				result.got = cert;
				result.accepted = false;
			} else {
				// if no "important" field changed, just accept it
				result.status = CW.CERT_STORED;
				cert.store(host);
			}

		} else {
			result.status = CW.CERT_STORED;
			storedCert.seen();
			storedCert.store(host);
		}
	}
}

async function checkConnection(url, securityInfo, tabId, cancel) {
	if (CW.enabled === false || CW.storageInitialized === false) {
		cancel.flag = true;
	}

	let host;
	try {
		const match = new RegExp("([a-z]+)://([^/:]+)").exec(url);
		//const baseUrl = match[0];
		host = match[2].replace(new RegExp("\\.$"), ""); // remove trailing .

		if (tabId === -1) {
			CW.logDebug("Request to", url, "not made in a tab");
			// TODO: what to do with requests not attached to tabs?
			return;
		}

		const certChecksSetting = CW.getSetting("certChecks");
		if (certChecksSetting === "domain") {
			const tab = await browser.tabs.get(tabId);
			const tabHost = new RegExp("://([^/]+)").exec(tab.url)[1]
					.replace(new RegExp("\\.$"), ""); // remove trailing .
			if (host !== tabHost) {
				CW.logDebug("Ignoring request to", host, "from tab with host", tabHost,
						"(setting is", certChecksSetting, ")");
				return;
			}
		}

		const ignoredDomains = CW.getSetting("ignoredDomains", []);
		const blockedDomains = CW.getSetting("blockedDomains", []);
		if (isDomainInList(host, ignoredDomains)) {
			return;
		}
		if (isDomainInList(host, blockedDomains)) {
			cancel.flag = true;
			cancel.silent = true;
			return;
		}

		if (securityInfo.state === "secure" || securityInfo.state === "weak") {
			const result = new CW.CheckResult(host);
			const strictMode = CW.getSetting("strictMode", true)
			const userApprovalRequired = CW.getSetting("userApprovalRequired", true)
			await analyzeCert(host, securityInfo, result);

			if ((strictMode && result.status === CW.CERT_TOFU) || (result.status === CW.CERT_CHANGED && userApprovalRequired)) {
				cancel.flag = true;
			}

			CW.logDebug(host, result.status.text);

			const tab = CW.getTab(tabId);
			tab.addResult(result);
			CW.updateTabIcon(tabId);
			if (result.status === CW.CERT_REJECTED) {
				cancel.flag = true;
				cancel.silent = true;
			}
		}
	} catch (e) {
		CW.logDebug("Error during connection checking", e);

		// add an internal error result
		const tab = CW.getTab(tabId);
		tab.addResult(new CW.CheckResult(host ? host : ""));
		CW.updateTabIcon(tabId);
	}
	return;
}

function sendNotificationBlocked() {
	browser.notifications.create({
		"type": "basic",
		"iconUrl": browser.runtime.getURL("icons/cw_16_changed.png"),
		"title": "Loading blocked",
		"message": "Certificates have been changed or strict mode is enabled. Please check extension."
	});
}

async function onHeadersReceived(details) {
	// only query securityInfo and then quickly return
	// checkConnection() is executed async
	// this makes blocking the request as short as possible
	let cancel = {flag: false, silent: false};

	const securityInfo = await browser.webRequest.getSecurityInfo(details.requestId, {});
	await checkConnection(details.url, securityInfo, details.tabId, cancel);
	if (cancel.flag === true) {
		if (!cancel.silent) {
			sendNotificationBlocked();
		}
		return {'cancel': true};
	}
	return;
}

browser.webRequest.onHeadersReceived.addListener(
	onHeadersReceived,
	{urls: [
		"https://*/*",
		"wss://*/*"
	]},
	// we have to set the option "blocking" for browser.webRequest.getSecurityInfo
	["blocking"]
);
