console.log("PhishHunt content script loaded");

chrome.runtime.onMessage.addListener((message) => {
    console.log("PhishHunt message received:", message);

    if (message.type === "PHISHING_DETECTED") {
        showPhishingWarning(message.url);
    }
});

function showPhishingWarning(url) {

    // Prevent duplicate warnings
    if (document.getElementById("phishhunt-warning")) {
        return;
    }

    const warning = document.createElement("div");

    warning.id = "phishhunt-warning";

    warning.innerHTML = `
        <div style="
            position: fixed;
            top: 20px;
            right: 20px;
            width: 360px;
            background: #171717;
            color: white;
            padding: 20px;
            border-radius: 14px;
            box-shadow: 0 8px 30px rgba(0,0,0,0.5);
            z-index: 2147483647;
            font-family: Arial, sans-serif;
            border: 2px solid #ff3333;
        ">
            <div style="
                font-size: 22px;
                font-weight: bold;
                color: #ff4444;
                margin-bottom: 10px;
            ">
                ⚠️ PHISHING DETECTED
            </div>

            <div style="
                font-size: 14px;
                margin-bottom: 12px;
                word-break: break-all;
            ">
                PhishHunt detected a potentially dangerous URL.
            </div>

            <div style="
                font-size: 12px;
                color: #cccccc;
                margin-bottom: 15px;
                word-break: break-all;
            ">
                ${url}
            </div>

            <button id="phishhunt-close" style="
                background: #ff4444;
                color: white;
                border: none;
                padding: 9px 18px;
                border-radius: 7px;
                cursor: pointer;
                font-weight: bold;
            ">
                Close Warning
            </button>
        </div>
    `;

    document.documentElement.appendChild(warning);

    document
        .getElementById("phishhunt-close")
        .addEventListener("click", () => {
            warning.remove();
        });
}