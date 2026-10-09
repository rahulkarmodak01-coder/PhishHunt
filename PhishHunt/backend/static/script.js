async function analyzeURL() {

    const input = document.getElementById("urlInput");

    const button = document.getElementById("analyzeButton");

    const url = input.value.trim();


    if (!url) {

        showError("Please enter a URL.");

        return;

    }


    hideError();

    hideResults();

    showLoading();


    button.disabled = true;


    try {

        const response = await fetch("/api/analyze", {

            method: "POST",

            headers: {
                "Content-Type": "application/json"
            },

            body: JSON.stringify({
                url: url
            })

        });


        const data = await response.json();


        if (!response.ok) {

            throw new Error(
                data.error || "Analysis failed."
            );

        }


        displayResults(data);


    } catch (error) {

        showError(
            error.message ||
            "Unable to connect to PhishHunt API."
        );

    } finally {

        hideLoading();

        button.disabled = false;

    }

}


function displayResults(data) {

    document.getElementById("analyzedURL").textContent =
        data.url;


    document.getElementById("finalResult").textContent =
        data.final_result;


    document.getElementById("mlPrediction").textContent =
        data.ml_prediction;


    document.getElementById("mlConfidence").textContent =
        data.ml_confidence + "%";


    document.getElementById("securityDecision").textContent =
        data.security_decision;


    document.getElementById("riskScore").textContent =
        data.risk_score + "/100";


    document.getElementById("confidenceFill").style.width =
        data.ml_confidence + "%";


    document.getElementById("riskFill").style.width =
        data.risk_score + "%";


    updateResultAppearance(
        data.final_result
    );


    displayIndicators(
        data.security_indicators
    );


    document
        .getElementById("resultSection")
        .classList.remove("hidden");

}


function updateResultAppearance(result) {

    const resultText =
        document.getElementById("finalResult");

    const resultIcon =
        document.getElementById("resultIcon");


    if (result === "LEGITIMATE") {

        resultText.style.color = "#22c55e";

        resultIcon.textContent = "✓";

        resultIcon.style.color = "#22c55e";

        resultIcon.style.background =
            "rgba(34,197,94,0.15)";

    }

    else if (result === "SUSPICIOUS") {

        resultText.style.color = "#f59e0b";

        resultIcon.textContent = "!";

        resultIcon.style.color = "#f59e0b";

        resultIcon.style.background =
            "rgba(245,158,11,0.15)";

    }

    else {

        resultText.style.color = "#ef4444";

        resultIcon.textContent = "✕";

        resultIcon.style.color = "#ef4444";

        resultIcon.style.background =
            "rgba(239,68,68,0.15)";

    }

}


function displayIndicators(indicators) {

    const container =
        document.getElementById("indicators");


    container.innerHTML = "";


    if (!indicators || indicators.length === 0) {

        container.textContent =
            "No security indicators detected.";

        return;

    }


    indicators.forEach(indicator => {

        const element =
            document.createElement("span");

        element.className = "indicator";

        element.textContent = indicator;

        container.appendChild(element);

    });

}


function showLoading() {

    document
        .getElementById("loading")
        .classList.remove("hidden");

}


function hideLoading() {

    document
        .getElementById("loading")
        .classList.add("hidden");

}


function showError(message) {

    document
        .getElementById("errorBox")
        .classList.remove("hidden");


    document
        .getElementById("errorMessage")
        .textContent = message;

}


function hideError() {

    document
        .getElementById("errorBox")
        .classList.add("hidden");

}


function hideResults() {

    document
        .getElementById("resultSection")
        .classList.add("hidden");

}


function resetAnalysis() {

    document
        .getElementById("urlInput")
        .value = "";


    hideResults();

    hideError();


    window.scrollTo({

        top: 0,

        behavior: "smooth"

    });


    document
        .getElementById("urlInput")
        .focus();

}


/* Press ENTER to analyze */

document
    .getElementById("urlInput")
    .addEventListener("keydown", function(event) {

        if (event.key === "Enter") {

            analyzeURL();

        }

    });