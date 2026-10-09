const API_URL = "http://127.0.0.1:5000/api/analyze";

const urlElement = document.getElementById("url");
const analyzeButton = document.getElementById("analyzeBtn");

const loadingElement = document.getElementById("loading");
const resultElement = document.getElementById("result");
const errorElement = document.getElementById("error");

const resultTitle = document.getElementById("resultTitle");
const mlPrediction = document.getElementById("mlPrediction");
const mlConfidence = document.getElementById("mlConfidence");
const riskScore = document.getElementById("riskScore");
const securityDecision = document.getElementById("securityDecision");

let currentUrl = "";


/*
 * Get the URL of the currently active Chrome tab.
 */
async function getCurrentTabUrl() {
    const tabs = await chrome.tabs.query({
        active: true,
        lastFocusedWindow: true
    });

    if (!tabs || tabs.length === 0 || !tabs[0].url) {
        throw new Error("Could not determine the current website URL.");
    }

    return tabs[0].url;
}


/*
 * Display the current URL in the popup.
 */
async function loadCurrentUrl() {
    try {
        currentUrl = await getCurrentTabUrl();

        urlElement.textContent = currentUrl;

    } catch (error) {
        urlElement.textContent = "Unable to read current URL.";
        showError(error.message);
    }
}


/*
 * Analyze the current URL using the PhishHunt Flask API.
 */
async function analyzeUrl() {

    if (!currentUrl) {
        showError("No URL available for analysis.");
        return;
    }

    hideError();
    hideResult();

    analyzeButton.disabled = true;
    loadingElement.style.display = "block";

    try {

        const response = await fetch(API_URL, {
            method: "POST",

            headers: {
                "Content-Type": "application/json"
            },

            body: JSON.stringify({
                url: currentUrl
            })
        });

        const data = await response.json();

        if (!response.ok || !data.success) {
            throw new Error(
                data.error || "PhishHunt API returned an error."
            );
        }

        displayResult(data);

    } catch (error) {

        console.error("PhishHunt error:", error);

        showError(
            "Could not connect to PhishHunt backend. " +
            "Make sure the Flask server is running."
        );

    } finally {

        analyzeButton.disabled = false;
        loadingElement.style.display = "none";
    }
}


/*
 * Display analysis result.
 */
function displayResult(data) {

    const finalResult = data.final_result || "UNKNOWN";

    resultTitle.textContent = finalResult;

    // Remove previous result classes.
    resultTitle.classList.remove(
        "legitimate",
        "suspicious",
        "phishing"
    );

    // Apply result color.
    if (finalResult === "LEGITIMATE") {

        resultTitle.classList.add("legitimate");

    } else if (finalResult === "SUSPICIOUS") {

        resultTitle.classList.add("suspicious");

    } else if (finalResult === "PHISHING") {

        resultTitle.classList.add("phishing");
    }


    mlPrediction.textContent =
        data.ml_prediction || "-";


    if (typeof data.ml_confidence === "number") {

        mlConfidence.textContent =
            data.ml_confidence.toFixed(2) + "%";

    } else {

        mlConfidence.textContent = "-";
    }


    if (typeof data.risk_score === "number") {

        riskScore.textContent =
            data.risk_score + "/100";

    } else {

        riskScore.textContent = "-";
    }


    securityDecision.textContent =
        data.security_decision || "-";


    resultElement.style.display = "block";
}


/*
 * Display an error message.
 */
function showError(message) {

    errorElement.textContent = message;
    errorElement.style.display = "block";
}


/*
 * Hide error message.
 */
function hideError() {

    errorElement.style.display = "none";
}


/*
 * Hide previous result.
 */
function hideResult() {

    resultElement.style.display = "none";
}


/*
 * Analyze button.
 */
analyzeButton.addEventListener("click", analyzeUrl);


/*
 * Load current website when popup opens.
 */
loadCurrentUrl();