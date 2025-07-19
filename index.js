// IMPORT STATEMENTS
import crypto from "crypto";
import fs from "fs";
import http from "http";

// CONSTANTS AND FUNCTION DEFINITIONS
const PORT = process.env.PORT;
const DbFile = "data.json";
let database = readDatabase();

const HEADERS = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
}

const storedHashes = {
    q1: crypto.createHash("sha256").update(process.env.Q1).digest("hex"),
    q2: crypto.createHash("sha256").update(process.env.Q2).digest("hex"),
    q3: crypto.createHash("sha256").update(process.env.Q3).digest("hex"),
}

function readDatabase() {
    try {
        const file = fs.readFileSync(DbFile);
        const db = JSON.parse(file);
        return db;
    } catch (err) {
        throw (err);
    }
}

function writeDatabase(data) {
    const json = JSON.stringify(data);
    fs.writeFileSync(DbFile, json);
}

function updateDatabase(data) {
    if (typeof data === "string") {
        return "Invalid JSON";
    } else {
        database.push(data);
        writeDatabase(database);
    }
}

function encrypt(text, key ,iv) {
    const cipher = crypto.createCipheriv("aes-128-ccm", key, iv, { authTagLength: 16 });
    const encryption = Buffer.concat([cipher.update(text, "utf8"), cipher.final()]);
    const tag = cipher.getAuthTag();

    return { encrypted: encryption.toString("hex"), tag: tag.toString("hex"), iv: iv.toString("hex") };
}

function decrypt(encryptedHex, key, ivHex, tagHex) {
    const encrypted = Buffer.from(encryptedHex, "hex");
    const iv = Buffer.from(ivHex, "hex");
    const tag = Buffer.from(tagHex, "hex");
    const decipher = crypto.createDecipheriv("aes-128-ccm", key, iv, { authTagLength: 16 });
    decipher.setAuthTag(tag);
    const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
    return decrypted.toString("utf8");
}

// PROGRAM
http.createServer((req, res) => {
    if (req.method === "OPTIONS") {
    res.writeHead(200, {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
        "Access-Control-Max-Age": 86400,
    });
    return res.end();
}
    if (req.method === "GET" && req.url === "/db") {
        const file = readDatabase();
        const response = JSON.stringify(file);
        res.writeHead(200, HEADERS);
        res.end(response);
    } else if (req.method === "POST" && req.url === "/db") {
        let data = "";
        req.on("data", chunk => data += chunk);

        req.on("end", () => {
            const parsed = JSON.parse(data);
            const answers = {
                q1: crypto.createHash("sha256").update(parsed.q1).digest("hex"),
                q2: crypto.createHash("sha256").update(parsed.q2).digest("hex"),
                q3: crypto.createHash("sha256").update(parsed.q3).digest("hex"),
            }
            let count = 0;
            if (storedHashes.q1 === answers.q1) count++;
            if (storedHashes.q2 === answers.q2) count++;
            if (storedHashes.q3 === answers.q3) count++;

            const key = crypto.randomBytes(16);
            const iv = crypto.randomBytes(12);
            const values = encrypt(parsed.msg, key, iv);

            if (count >= 3) {
                const newUser = {
                    username: values,
                    iv: iv.toString("hex"),
                    key: key.toString("hex"),
                }
                updateDatabase(newUser);
                res.writeHead(200, HEADERS);
                res.end(JSON.stringify({ message: "Added item successfully..." }))
            } else {
                res.writeHead(401, HEADERS);
                res.end(JSON.stringify({ message: "Unauthorized Access..." }));
            }
        });
    } else if (req.method === "DELETE" && req.url === "/db") {
        let data = "";
        req.on("data", chunk => data += chunk);

        req.on("end", () => {
            const parsed = JSON.parse(data);
            const answers = {
                q1: crypto.createHash("sha256").update(parsed.q1).digest("hex"),
                q2: crypto.createHash("sha256").update(parsed.q2).digest("hex"),
                q3: crypto.createHash("sha256").update(parsed.q3).digest("hex"),
            }
            let count = 0;
            if (storedHashes.q1 === answers.q1) count++;
            if (storedHashes.q2 === answers.q2) count++;
            if (storedHashes.q3 === answers.q3) count++;

            if (count >= 3) {
                writeDatabase([]);
                res.writeHead(200, HEADERS);
                res.end(JSON.stringify({ mesage: "Deleted database..." }));
            } else {
                res.writeHead(401, HEADERS);
                res.end(JSON.stringify({ message: "Unauthorized Access..." }));
            }
        });
    }
}).listen(PORT, "0.0.0.0", () => {
    console.log(`Listening on http://0.0.0.0:${PORT}`);
});
