// IMPORT STATEMENTS
import crypto from "crypto";
import fs from "fs";
import http from "http";
import { Server } from "socket.io";
import dotenv from "dotenv";
dotenv.config();

// CONSTANTS AND FUNCTION DEFINITIONS
const PORT = process.env.PORT;
const DbFile = "data.json";

const HEADERS = {
  "Content-Type": "application/json",
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};


const storedHashes = {
    Q1: crypto.createHash("sha256").update(process.env.Q1).digest("base64"),
    Q2: crypto.createHash("sha256").update(process.env.Q2).digest("base64"),
    Q3: crypto.createHash("sha256").update(process.env.Q3).digest("base64"),
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
        const db = readDatabase();
        db.push(data);
        writeDatabase(db);
    }
}

function encrypt(text, key, iv) {
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

function decryptMsg(encryptedstuff) {
    const { encrypted, tag, iv } = encryptedstuff.msg;
    const keyHex = encryptedstuff.key;

    try {
        const decrypted = decrypt(encrypted, Buffer.from(keyHex, "hex"), iv, tag);
        return decrypted;
    } catch(err) {
        console.error(err);
        return "DECRYPTED [ERROR]"
    }
}

// PROGRAM
const server = http.createServer((req, res) => {
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
        const decryptedFile = file.map(entry => ({
            original: entry.msg.encrypted,
            decrypted: decryptMsg(entry),
        }));

        res.writeHead(200, HEADERS);
        res.end(JSON.stringify(decryptedFile, null, 2));
    } else if (req.method === "POST" && req.url === "/db") {
        let data = "";
        req.on("data", chunk => data += chunk);

        req.on("end", () => {
            const parsed = JSON.parse(data);
            const answers = {
                Q1: crypto.createHash("sha256").update(parsed.Q1).digest("base64"),
                Q2: crypto.createHash("sha256").update(parsed.Q2).digest("base64"),
                Q3: crypto.createHash("sha256").update(parsed.Q3).digest("base64"),
            }
            let count = 0;
            if (storedHashes.Q1 === answers.Q1) count++;
            if (storedHashes.Q2 === answers.Q2) count++;
            if (storedHashes.Q3 === answers.Q3) count++;

            const key = crypto.randomBytes(16);
            const iv = crypto.randomBytes(12);
            const msg = encrypt(parsed.msg, key, iv);

            if (count >= 3) {
                const newUser = {
                    msg: msg,
                    key: key.toString("hex"),
                }
                updateDatabase(newUser);

                // Emit the message to all connected clients
                io.emit("message", newUser);

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
                Q1: crypto.createHash("sha256").update(parsed.Q1).digest("base64"),
                Q2: crypto.createHash("sha256").update(parsed.Q2).digest("base64"),
                Q3: crypto.createHash("sha256").update(parsed.Q3).digest("base64"),
            }
            let count = 0;
            if (storedHashes.Q1 === answers.Q1) count++;
            if (storedHashes.Q2 === answers.Q2) count++;
            if (storedHashes.Q3 === answers.Q3) count++;

            if (count >= 3) {
                writeDatabase([]);
                res.writeHead(200, HEADERS);
                res.end(JSON.stringify({ message: "Deleted database..." }));
            } else {
                res.writeHead(401, HEADERS);
                res.end(JSON.stringify({ message: "Unauthorized Access..." }));
            }
        });
    }
});

const io = new Server(server, {
    cors: { origin: "*" },
});

io.on("connection", socket => {
    socket.on("message", (message) => {
        console.log("Received message event (unused):", message);
    });
    socket.on("disconnect", () => {
        console.log("Client disconnected:", socket.id);
    });
});

server.listen(PORT,"0.0.0.0", () => {
    console.log(`Listening on http://localhost:${PORT}`);
});
