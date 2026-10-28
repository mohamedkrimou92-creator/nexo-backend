
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { createClient } = require("@supabase/supabase-js");

const app = express();
app.set("trust proxy", 1);

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH;
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN;
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SECRET_KEY = process.env.SUPABASE_SECRET_KEY;

if (
  !JWT_SECRET ||
  JWT_SECRET.length < 32 ||
  !ADMIN_USERNAME ||
  !ADMIN_PASSWORD_HASH ||
  !FRONTEND_ORIGIN ||
  !SUPABASE_URL ||
  !SUPABASE_SECRET_KEY
) {
  console.error("Missing required environment variables.");
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SECRET_KEY, {
  auth: {
    autoRefreshToken: false,
    persistSession: false
  }
});

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
  message: { error: "Too many attempts. Try again later." }
});

const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many registration attempts. Try again later." }
});

function getToken(req) {
  const header = req.headers.authorization || "";
  return header.startsWith("Bearer ") ? header.slice(7) : "";
}

function verifyToken(req, res, next, expectedRole) {
  const token = getToken(req);

  if (!token) {
    return res.status(401).json({ error: "Authentication required." });
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET, {
      algorithms: ["HS256"]
    });

    if (payload.role !== expectedRole) {
      return res.status(403).json({ error: "Access denied." });
    }

    req.auth = payload;
    next();
  } catch {
    return res.status(401).json({ error: "Invalid or expired session." });
  }
}

function requireAdmin(req, res, next) {
  verifyToken(req, res, next, "admin");
}

function requireUser(req, res, next) {
  verifyToken(req, res, next, "user");
}

app.get("/api/health", (req, res) => {
  res.json({ status: "ok", service: "MRHBA BIKOM API" });
});

// Create a user account
app.post("/api/auth/register", registerLimiter, async (req, res) => {
  try {
    const { username, email, password } = req.body || {};

    if (
      typeof username !== "string" ||
      typeof email !== "string" ||
      typeof password !== "string"
    ) {
      return res.status(400).json({ error: "Please fill in all fields." });
    }

    const cleanUsername = username.trim();
    const cleanEmail = email.trim().toLowerCase();

    if (!/^[a-zA-Z0-9_]{3,30}$/.test(cleanUsername)) {
      return res.status(400).json({
        error: "Username must be 3-30 characters using letters, numbers or _."
      });
    }

    if (
      cleanEmail.length > 254 ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)
    ) {
      return res.status(400).json({ error: "Please enter a valid email." });
    }

    if (password.length < 8 || password.length > 72) {
      return res.status(400).json({
        error: "Password must be between 8 and 72 characters."
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const { data, error } = await supabase
      .from("app_users")
      .insert({
        username: cleanUsername,
        email: cleanEmail,
        password_hash: passwordHash
      })
      .select("id, username, email, created_at")
      .single();

    if (error) {
      if (error.code === "23505") {
        return res.status(409).json({
          error: "Username or email is already registered."
        });
      }

      console.error("Registration database error:", error.code);
      return res.status(500).json({ error: "Could not create account." });
    }

    const token = jwt.sign(
      { role: "user" },
      JWT_SECRET,
      {
        subject: data.id,
        algorithm: "HS256",
        expiresIn: "7d"
      }
    );

    return res.status(201).json({
      message: "Account created successfully.",
      token,
      user: data
    });
  } catch (error) {
    console.error("Registration error:", error.message);
    return res.status(500).json({ error: "Server error." });
  }
});

// Log in with username or email
app.post("/api/auth/login", loginLimiter, async (req, res) => {
  try {
    const { identifier, password } = req.body || {};

    if (
      typeof identifier !== "string" ||
      typeof password !== "string" ||
      identifier.length > 254 ||
      password.length > 72
    ) {
      return res.status(400).json({ error: "Invalid login details." });
    }

    const value = identifier.trim();
    const isEmail = value.includes("@");

    const { data: user, error } = await supabase
      .from("app_users")
      .select("id, username, email, password_hash, created_at")
      .eq(isEmail ? "email" : "username", isEmail ? value.toLowerCase() : value)
      .maybeSingle();

    if (error) {
      console.error("Login database error:", error.code);
      return res.status(500).json({ error: "Server error." });
    }

    const passwordMatches = user
      ? await bcrypt.compare(password, user.password_hash)
      : false;

    if (!user || !passwordMatches) {
      return res.status(401).json({
        error: "Incorrect username/email or password."
      });
    }

    const token = jwt.sign(
      { role: "user" },
      JWT_SECRET,
      {
        subject: user.id,
        algorithm: "HS256",
        expiresIn: "7d"
      }
    );

    return res.json({
      message: "Login successful.",
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        created_at: user.created_at
      }
    });
  } catch (error) {
    console.error("User login error:", error.message);
    return res.status(500).json({ error: "Server error." });
  }
});

// Check the signed-in user's session
app.get("/api/auth/me", requireUser, async (req, res) => {
  try {
    const { data: user, error } = await supabase
      .from("app_users")
      .select("id, username, email, created_at")
      .eq("id", req.auth.sub)
      .maybeSingle();

    if (error) {
      console.error("User lookup error:", error.code);
      return res.status(500).json({ error: "Server error." });
    }

    if (!user) {
      return res.status(404).json({ error: "Account not found." });
    }

    return res.json({ authenticated: true, user });
  } catch (error) {
    console.error("Session check error:", error.message);
    return res.status(500).json({ error: "Server error." });
  }
});

// Existing admin login
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
      return res.status(401).json({
        error: "Incorrect username or password."
      });
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

    return res.json({
      message: "Login successful.",
      token,
      expiresIn: 1800
    });
  } catch (error) {
    console.error("Admin login error:", error.message);
    return res.status(500).json({ error: "Server error." });
  }
});

app.get("/api/admin/me", requireAdmin, (req, res) => {
  res.json({
    authenticated: true,
    username: req.auth.sub,
    role: "admin"
  });
});

app.use((req, res) => {
  res.status(404).json({ error: "Route not found." });
});

app.listen(PORT, () => {
  console.log(`MRHBA BIKOM API listening on port ${PORT}`);
});
