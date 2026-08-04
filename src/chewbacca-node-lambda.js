exports.handler = async (event) => {
    console.log("Incoming event:", JSON.stringify(event));

    const name = event.queryStringParameters?.name || "Unknown";

    const response = {
        message: `HELLO ${name.toUpperCase()} FROM NODE!`,
    };

    console.log("Response:", JSON.stringify(response));

    return {
        statusCode: 200,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(response),
    };
};

exports.handler = async (event) => {
    const claims = event.requestContext?.authorizer?.claims || {};
    const groups = claims["cognito:groups"] || [];

    const path = event.resource;

    if (path === "/node" && !groups.includes("admins")) {
        return {
            statusCode: 403,
            body: JSON.stringify({ error: "Access denied" })
        };
    }

    return {
        statusCode: 200,
        body: JSON.stringify({
            message: "Access granted",
            groups: groups
        }),
    };
};