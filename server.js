const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcrypt");
const bodyParser = require("body-parser");
const session = require("express-session");
const cors = require("cors");
const path = require("path");

const app = express();

app.use(cors());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static(__dirname));

app.use(session({
    secret: "secretkey",
    resave: false,
    saveUninitialized: true
}));

// DATABASE CONNECTION
const db = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "1406",
    database: "error_analyzer"
});

db.connect((err) => {
    if (err) {
        console.log("Database connection failed");
    } else {
        console.log("Connected to MySQL");
    }
});


// ================= REGISTER =================
app.post("/register", async (req, res) => {
    const { username, regemail, regpassword } = req.body;
    const hashedPassword = await bcrypt.hash(regpassword, 10);

    db.query(
        "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
        [username, regemail, hashedPassword],
        (err) => {
            if (err) {
                res.json({ message: "Email already exists" });
            } else {
                res.json({ message: "Registration successful" });
            }
        }
    );
});


// ================= LOGIN =================
app.post("/login", (req, res) => {
    const { email, pass } = req.body;

    db.query(
        "SELECT * FROM users WHERE email = ?",
        [email],
        async (err, results) => {
            if (results.length > 0) {
                const valid = await bcrypt.compare(pass, results[0].password);

                if (valid) {
                    req.session.user = email;
                    res.json({ message: "Login successful" });
                } else {
                    res.json({ message: "Wrong password" });
                }
            } else {
                res.json({ message: "User not found" });
            }
        }
    );
});


// ================= ERROR ANALYZER =================
app.post("/analyze", (req, res) => {

    if (!req.session.user) {
        return res.json({ message: "Not logged in" });
    }

    const { language, code } = req.body;

    let result = "No errors found.";
    let suggestion = "Code looks good.";

    if (language === "JAVA" || language === "C") {
        if (!code.includes(";")) {
            result = "Missing semicolon.";
            suggestion = "Add semicolon at end of statements.";
        }
    }

    if (language === "PYTHON") {
        if (code.includes("if") && !code.includes(":")) {
            result = "Missing colon.";
            suggestion = "Add ':' after if condition.";
        }
    }

    if (language === "JAVASCRIPT") {
        if (code.split("{").length !== code.split("}").length) {
            result = "Unmatched brackets.";
            suggestion = "Check opening and closing braces.";
        }
    }

    // SAVE TO HISTORY
    db.query(
        "INSERT INTO history (user_email, language, code, result) VALUES (?, ?, ?, ?)",
        [req.session.user, language, code, result]
    );

    res.json({ result, suggestion });
});


// ================= HISTORY =================
app.get("/history", (req, res) => {

    if (!req.session.user) {
        return res.json({ message: "Not logged in" });
    }

    db.query(
        "SELECT language, result, created_at FROM history WHERE user_email = ? ORDER BY created_at DESC",
        [req.session.user],
        (err, results) => {
            res.json(results);
        }
    );
});


// ================= LOGOUT =================
app.get("/logout", (req, res) => {
    req.session.destroy();
    res.json({ message: "Logged out" });
});


// START SERVER
app.listen(3000, () => {
    console.log("Server running at http://localhost:3000");
});