"use strict";
/* global Set, convertDate, timeDiffToToday */

/*
 * The script for the browser action popup.
 */

browser.runtime.getBackgroundPage().then((bg) => {
const CW = bg.getCW();

const changed = new Set();
const tofu = new Set();
const stored = new Set();

function showChangedValidity(validity, otherValidity, color, parent) {
	let span = document.createElement("span");
	span.textContent = browser.i18n.getMessage(
			"popupChangedFieldValidityStart",
			[convertDate(validity.start), timeDiffToToday(validity.start)]
	);
	parent.appendChild(span);
	if (validity.start !== otherValidity.start) {
		span.style.color = color;
	}

	parent.appendChild(document.createElement("br"));

	span = document.createElement("span");
	span.textContent = browser.i18n.getMessage(
			"popupChangedFieldValidityEnd",
			[convertDate(validity.end), timeDiffToToday(validity.end)]
	);
	parent.appendChild(span);
	if (validity.end !== otherValidity.end) {
		span.style.color = color;
	}
}

function showChangedSubject(subject, otherSubject, color, parent) {
	const sSplit = subject.match(new RegExp("[A-Z]+=([^,\"]+|\"[^\"]+\")", "g"));
	const oSplit = otherSubject.match(new RegExp("[A-Z]+=([^,\"]+|\"[^\"]+\")", "g"));

	let comma;
	for (const part of sSplit) {
		const span = document.createElement("span");
		span.textContent = part;
		parent.appendChild(span);

		// check if this part exist in the other subject
		let foundInOther = false;
		for (const oPart of oSplit) {
			if (part === oPart) {
				foundInOther = true;
				break;
			}
		}
		if (!foundInOther) {
			span.style.color = color;
		}

		comma = document.createTextNode(", ");
		parent.appendChild(comma);
	}
	// remove trailing comma
	if (comma) {
		parent.removeChild(comma);
	}
}

function addResult(result) {
	function insertToList(listId, host) {
		const list = document.getElementById(listId);
		const li = document.createElement("li");
		li.textContent = host;
		list.appendChild(li);
	}

	if (result.status === CW.CERT_TOFU) {
		if (!tofu.has(result.host)) {
			tofu.add(result.host);
			insertToList("tofuList", result.host);
		}
	} else if (result.status === CW.CERT_STORED) {
		// there may be the case that a TOFU certificate was re-used in a later connection
		// because of this, we remove it from stored UI since it is new for this "page"
		if (!stored.has(result.host) && !tofu.has(result.host)) {
			stored.add(result.host);
			insertToList("storedList", result.host);
		}
	} else if (result.status === CW.CERT_CHANGED) {
		if (!changed.has(result.host)) {
			changed.add(result.host);

			const list = document.getElementById("changedList");
			const li = document.createElement("li");
			li.textContent = result.host;
			list.appendChild(li);

			const ul = document.createElement("ul");
			for (const field of Object.keys(result.changes)) {
				const nestedLi = document.createElement("li");
				const b = document.createElement("b");
				if (field === "subject") {
					b.textContent = browser.i18n.getMessage("popupChangedFieldSubject");
				} else if (field === "issuer") {
					b.textContent = browser.i18n.getMessage("popupChangedFieldIssuer");
				} else if (field === "validity") {
					b.textContent = browser.i18n.getMessage("popupChangedFieldValidity");
				} else if (field === "subjectPublicKeyInfoDigest") {
					b.textContent = browser.i18n.getMessage("popupChangedFieldPublicKey");
				} else if (field === "fingerprint") {
					b.textContent = browser.i18n.getMessage("popupChangedFieldFingerprint");
				} else if (field === "serialNumber") {
					b.textContent = browser.i18n.getMessage("popupChangedFieldSerialNumber");
				} else {
					b.textContent = field;
				}
				nestedLi.appendChild(b);

				if (field === "subject" || field === "issuer" || field === "validity") {
					nestedLi.appendChild(document.createTextNode(" " + browser.i18n.getMessage("popupChanged")));

					const table = document.createElement("table");
					const r1 = document.createElement("tr");
					const r2 = document.createElement("tr");
					const e11 = document.createElement("td");
					const e12 = document.createElement("td");
					const e21 = document.createElement("td");
					const e22 = document.createElement("td");

					e11.textContent = browser.i18n.getMessage("popupChangedStored");
					if (field === "validity") {
						showChangedValidity(result.changes[field].stored, result.changes[field].got, "blue", e12);
					} else {
						showChangedSubject(result.changes[field].stored, result.changes[field].got, "blue", e12);
					}

					e21.textContent = browser.i18n.getMessage("popupChangedNew");
					if (field === "validity") {
						showChangedValidity(result.changes[field].got, result.changes[field].stored, "orange", e22);
					} else {
						showChangedSubject(result.changes[field].got, result.changes[field].stored, "orange", e22);
					}

					r1.appendChild(e11);
					r1.appendChild(e12);
					r2.appendChild(e21);
					r2.appendChild(e22);
					table.appendChild(r1);
					table.appendChild(r2);
					nestedLi.appendChild(table);
				} else {
					nestedLi.appendChild(document.createTextNode(" " + browser.i18n.getMessage("popupChanged")));
				}

				ul.appendChild(nestedLi);
			}
			li.appendChild(ul);

			const button = document.createElement("input");
			button.setAttribute("type", "button");
			button.setAttribute("value", browser.i18n.getMessage("popupAddChanged"));
			button.addEventListener("click", function() {
				button.disabled = true;
				CW.logInfo("Storing new certificate for", result.host);

				result.got.store(result.host);

				button.setAttribute("value", browser.i18n.getMessage("popupAddedChanged"));
			});
			li.appendChild(button);
		}
	} else {
		CW.logDebug("Got result that has no known type", result);
	}
}

function updateCounts() {
	document.getElementById("numChanged").textContent = changed.size;
	document.getElementById("numTofu").textContent = tofu.size;
	document.getElementById("numStored").textContent = stored.size;
}

function clearResults() {
	for (const name of ["tofuList", "storedList", "changedList"]) {
		const list = document.getElementById(name);
		while (list.firstChild) {
			list.removeChild(list.firstChild);
		}
	}
}

async function init() {
	const settingsLink = document.getElementById("settingsLink");
	settingsLink.addEventListener("click", function() {
		browser.runtime.openOptionsPage();
	});

	const storageLink = document.getElementById("storageLink");
	storageLink.addEventListener("click", function() {
		browser.tabs.create({
			active: true,
			url: "cw_storage.html"
		});
	});

	const state = document.getElementById("state");
	function updateStateText() {
		if (CW.enabled) {
			state.setAttribute("value", browser.i18n.getMessage("popupStateEnabled"));
			state.style.color = "";
			state.setAttribute("title", browser.i18n.getMessage("popupStateEnabledTooltip"));
		} else {
			state.setAttribute("value", browser.i18n.getMessage("popupStateDisabled"));
			state.style.color = "var(--color-red)";
			state.setAttribute("title", browser.i18n.getMessage("popupStateDisabledTooltip"));
		}
	}
	updateStateText();
	state.addEventListener("click", function(event) {
		event.preventDefault();
		CW.toggleEnabled();
		updateStateText();
	});

	const currentTab = await CW.Tab.getActiveTab();
	if (!currentTab) {
		return;
	}

	for (const result of currentTab.results) {
		addResult(result);
	}
	updateCounts();

	browser.runtime.onMessage.addListener((message) => {
		if (message.type === "tab.newResult" && message.tabId === currentTab.tabId) {
			addResult(currentTab.results[message.resultIndex]);
			updateCounts();
		} else if (message.type === "tab.resultsCleared" && message.tabId === currentTab.tabId) {
			changed.clear();
			tofu.clear();
			stored.clear();

			clearResults();
			updateCounts();
		}
	});
}
init();

}); // CW getter
