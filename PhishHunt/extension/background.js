const API_URL = "http://127.0.0.1:5000/api/analyze";

console.log("PhishHunt background service worker loaded.");


// ============================================================
// ANALYZE URL
// ============================================================

async function analyzeUrl(url) {

    console.log("Sending URL to PhishHunt:", url);

    try {

        const response = await fetch(API_URL, {
            method: "POST",

            headers: {
                "Content-Type": "application/json"
            },

            body: JSON.stringify({
                url: url
            })
        });

        console.log("API response status:", response.status);

        const data = await response.json();

        console.log("PhishHunt API result:", data);

        return data;

    } catch (error) {

        console.error(
            "PhishHunt background analysis error:",
            error
        );

        return null;
    }
}


// ============================================================
// SEND RESULT TO WEBPAGE
// ============================================================

function sendResultToPage(tabId, result, url) {

    chrome.tabs.sendMessage(
        tabId,
        {
            type: result.final_result === "PHISHING"
                ? "PHISHING_DETECTED"
                : result.final_result === "SUSPICIOUS"
                ? "SUSPICIOUS_DETECTED"
                : "LEGITIMATE_DETECTED",

            result: result,
            url: url
        },
        (response) => {

            if (chrome.runtime.lastError) {

                console.log(
                    "Could not send result to page:",
                    chrome.runtime.lastError.message
                );

                return;
            }

            console.log(
                "Result sent to webpage:",
                response
            );
        }
    );
}


// ============================================================
// AUTOMATIC WEBSITE ANALYSIS
// ============================================================

chrome.tabs.onUpdated.addListener(
    async (tabId, changeInfo, tab) => {

        console.log(
            "Tab updated:",
            tabId,
            changeInfo.status,
            tab.url
        );

        if (changeInfo.status !== "complete") {
            return;
        }

        const url = tab.url;

        if (
            !url ||
            (
                !url.startsWith("http://") &&
                !url.startsWith("https://")
            )
        ) {

            console.log(
                "Ignoring non-web URL:",
                url
            );

            return;
        }

        console.log(
            "Analyzing completed webpage:",
            url
        );

        const result = await analyzeUrl(url);

        if (!result || !result.success) {

            console.log(
                "No valid PhishHunt result."
            );

            return;
        }


        // ====================================================
        // SEND RESULT TO CONTENT SCRIPT
        // ====================================================

        sendResultToPage(
            tabId,
            result,
            url
        );


        // ====================================================
        // PHISHING
        // ====================================================

        if (result.final_result === "PHISHING") {

            console.log(
                "🚨 PHISHING DETECTED:",
                url
            );

            chrome.notifications.create(
                `phishhunt-${tabId}-${Date.now()}`,
                {
                    type: "basic",
                    iconUrl: "icon128.png",
                    title: "PhishHunt Warning",
                    message:
                        "This website may be a phishing threat."
                },
                (notificationId) => {

                    if (chrome.runtime.lastError) {

                        console.error(
                            "NOTIFICATION ERROR:",
                            chrome.runtime.lastError.message
                        );

                    } else {

                        console.log(
                            "NOTIFICATION CREATED:",
                            notificationId
                        );
                    }
                }
            );
        }


        // ====================================================
        // SUSPICIOUS
        // ====================================================

        else if (
            result.final_result === "SUSPICIOUS"
        ) {

            console.log(
                "⚠️ SUSPICIOUS WEBSITE:",
                url
            );

            chrome.notifications.create(
                `phishhunt-${tabId}-${Date.now()}`,
                {
                    type: "basic",
                    iconUrl: "icon128.png",
                    title: "PhishHunt Alert",
                    message:
                        "This website has suspicious URL characteristics."
                }
            );
        }


        // ====================================================
        // LEGITIMATE
        // ====================================================

        else {

            console.log(
                "✅ LEGITIMATE:",
                url
            );
        }
    }
);