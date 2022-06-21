const { startRegistration, startAuthentication } = SimpleWebAuthnBrowser;

// Registration
const statusRegister = document.getElementById("statusRegister");
const dbgRegister = document.getElementById("dbgRegister");

// Authentication
const statusAuthenticate = document.getElementById("statusAuthenticate");
const dbgAuthenticate = document.getElementById("dbgAuthenticate");


/**
 * Helper methods
 */

function printToDebug(elemDebug, title, output) {
  if (elemDebug.innerHTML !== "") {
    elemDebug.innerHTML += "\n";
  }
  elemDebug.innerHTML += `// ${title}\n`;
  elemDebug.innerHTML += `${output}\n`;
}

function resetDebug(elemDebug) {
  elemDebug.innerHTML = "";
}

function printToStatus(elemStatus, output) {
  elemStatus.innerHTML = output;
}

function resetStatus(elemStatus) {
  elemStatus.innerHTML = "";
}

function getPassStatus() {
  return "✅";
}

function getFailureStatus(message) {
  return `🛑 (Reason: ${message})`;
}

/**
 * Register Button
 */
document
  .getElementById("enroll")
  .addEventListener("click", async () => {
    resetStatus(statusRegister);
    resetDebug(dbgRegister);
    var username = document.getElementById("user").value;

    // Get options
    //const resp = await fetch("/generate-registration-options");
    let text1 = "/generate-registration-options/";
    let result = text1.concat(username);
    const resp = await fetch(result);
    const opts = await resp.json();
    printToDebug(
      dbgRegister,
      "Registration Options",
      JSON.stringify(opts, null, 2)
    );

    // Start WebAuthn Registration
    let regResp;
    try {
      regResp = await startRegistration(opts);
      printToDebug(
        dbgRegister,
        "Registration Response",
        JSON.stringify(regResp, null, 2)
      );
    } catch (err) {
      printToStatus(statusRegister, getFailureStatus(err));
      throw new Error(err);
    }

    // Send response to server
    let text2 = "/verify-registration-response/";
    let result1 = text2.concat(username)
    const verificationResp = await fetch(
      result1,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(regResp),
      }
    );

    // Report validation response
    const verificationRespJSON = await verificationResp.json();
    const { verified, msg } = verificationRespJSON;
    if (verified) {
      printToStatus(statusRegister, getPassStatus());
    } else {
      printToStatus(statusRegister, getFailureStatus(err));
    }
    printToDebug(
      dbgRegister,
      "Verification Response",
      JSON.stringify(verificationRespJSON, null, 2)
    );
  });

/**
 * Authenticate Button
 */
document
  .getElementById("continue")
  .addEventListener("click", async () => {
    resetStatus(statusAuthenticate);
    resetDebug(dbgAuthenticate);
    var username1 = document.getElementById("user").value;

    // Get options
    //const resp = await fetch("/generate-registration-options");
    let text3 = "/generate-authentication-options/";
    let result3 = text3.concat(username1);

    // Get options
    const resp = await fetch(result3);
    const opts = await resp.json();
    printToDebug(
      dbgAuthenticate,
      "Authentication Options/Error",
      JSON.stringify(opts, null, 2)
    );

    // Start WebAuthn Authentication
    let authResp;
    try {
      authResp = await startAuthentication(opts);
      printToDebug(
        dbgAuthenticate,
        "Authentication Response",
        JSON.stringify(authResp, null, 2)
      );
    } catch (err) {
      printToStatus(statusAuthenticate, getFailureStatus(err));
      throw new Error(err);
    }

    // Send response to server
    let text4 =   "/verify-authentication-response/";
    let result4 = text4.concat(username1);
    const verificationResp = await fetch(
      result4,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(authResp),
      }
    );

    // Report validation response
    const verificationRespJSON = await verificationResp.json();
    const { verified, msg } = verificationRespJSON;
    if (verified) {
      printToStatus(statusAuthenticate, getPassStatus());
    } else {
      printToStatus(statusAuthenticate, getFailureStatus(err));
    }
    printToDebug(
      dbgAuthenticate,
      "Verification Response",
      JSON.stringify(verificationRespJSON, null, 2)
    );
  });
