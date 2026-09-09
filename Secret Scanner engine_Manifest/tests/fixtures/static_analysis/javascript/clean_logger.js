// Clean logging utility
function logInfo(message, meta = {}) {
    const timestamp = new Date().toISOString();
    console.log(JSON.stringify({ timestamp, level: "info", message, ...meta }));
}

module.exports = { logInfo };
