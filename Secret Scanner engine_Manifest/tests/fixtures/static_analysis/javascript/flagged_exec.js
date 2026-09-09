const child_process = require("child_process");

function executePayload(command, code) {
    // Obvious flagged patterns: child_process.exec and eval
    child_process.exec(command, (err, stdout) => {
        if (err) console.error(err);
        eval(code);
    });
}

module.exports = { executePayload };
