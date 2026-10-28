
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
app.set("trust proxy", 1);

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH;
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN;

if (
  !JWT_SECRET ||
  JWT_SECRET.length < 32 ||
  !ADMIN_USERNAME ||
  !ADMIN_PASSWORD_HASH ||
  !FRONTEND_ORIGIN
) {
  console.error("Missing required environment variables.");
  process.exit(1);
}

app.use(helmet());

app.use(cors({
  origin: FRONTEND_ORIGIN,
  methods: ["GET", "POST"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

app.use(express.json({ limit: "10kb" }));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many login attempts. Try again later." }
});

function requireAdmin(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ")
    ? header.slice(7)
    : "";

  if (!token) {
    return res.status(401).json({ error: "Authentication required." });
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET, {
      algorithms: ["HS256"]
    });

    if (
      payload.role !== "admin" ||
      payload.sub !== ADMIN_USERNAME
    ) {
      return res.status(403).json({ error: "Access denied." });
    }

    req.admin = payload;
    next();
  } catch {
    return res.status(401).json({ error: "Invalid or expired session." });
  }
}

app.get("/api/health", (req, res) => {
  res.json({ status: "ok", service: "MRHBA BIKOM API" });
});

app.post("/api/admin/login", loginLimiter, async (req, res) => {
  try {
    const { username, password } = req.body || {};

    if (
      typeof username !== "string" ||
      typeof password !== "string" ||
      username.length > 100 ||
      password.length > 200
    ) {
      return res.status(400).json({ error: "Invalid login details." });
    }

    const usernameMatches = username === ADMIN_USERNAME;
    const passwordMatches = await bcrypt.compare(
      password,
      ADMIN_PASSWORD_HASH
    );

    if (!usernameMatches || !passwordMatches) {
      return res.status(401).json({ error: "Incorrect username or password." });
    }

    const token = jwt.sign(
      { role: "admin" },
      JWT_SECRET,
      {
        subject: ADMIN_USERNAME,
        algorithm: "HS256",
        expiresIn: "30m"
      }
    );

    res.json({
      message: "Login successful.",
      token,
      expiresIn: 1800
    });
  } catch (error) {
    console.error("Login error:", error.message);
    res.status(500).json({ error: "Server error." });
  }
});

app.get("/api/admin/me", requireAdmin, (req, res) => {
  res.json({
    authenticated: true,
    username: req.admin.sub,
    role: "admin"
  });
});

app.use((req, res) => {
  res.status(404).json({ error: "Route not found." });
});

app.listen(PORT, () => {
  console.log(`MRHBA BIKOM API listening on port ${PORT}`);
});
