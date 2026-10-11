
require("dotenv").config();

const express = require("express");
const http = require("http");
const path = require("path");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const helmet = require("helmet");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = process.env.PORT || 3000;
const DB_PATH = process.env.DB_PATH || "pytest.sqlite";
const DB_DIR = process.env.DB_DIR || ".";
const SESSION_SECRET = process.env.SESSION_SECRET;
const TEACHER_USERNAME = process.env.TEACHER_USERNAME || "teacher";
const TEACHER_PASSWORD_HASH = process.env.TEACHER_PASSWORD_HASH;

if (!SESSION_SECRET || SESSION_SECRET.length < 32) {
  console.error("ERROR: Set SESSION_SECRET to a random secret of at least 32 characters.");
  process.exit(1);
}

if (!TEACHER_PASSWORD_HASH) {
  console.error("ERROR: Set TEACHER_PASSWORD_HASH in Render Environment.");
  process.exit(1);
}

// Render uses a reverse proxy for HTTPS.
app.set("trust proxy", 1);

const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");

db.exec(`
  CREATE TABLE IF NOT EXISTS codes (
    code TEXT PRIMARY KEY,
    student TEXT,
    expires TEXT,
    used INTEGER DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS attempts (
    id INTEGER PRIMARY KEY,
    code TEXT,
    student TEXT,
    started TEXT,
    submitted TEXT,
    answers TEXT DEFAULT '{}',
    result TEXT,
    status TEXT DEFAULT 'in_progress',
    consent TEXT
  );

  CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY,
    attempt INTEGER,
    event TEXT,
    details TEXT,
    at TEXT
  );
`);

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "100kb" }));

app.use(
  session({
    name: "connect.sid",
    store: new SQLiteStore({
      db: "sessions.sqlite",
      dir: DB_DIR
    }),
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    proxy: true,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: "auto",
      maxAge: 8 * 60 * 60 * 1000
    }
  })
);

app.use(express.static(path.join(__dirname, "public")));

const questions = require("./questions.json");
const now = () => new Date().toISOString();

function auth(req, res, next) {
  if (req.session && req.session.teacher === true) {
    return next();
  }

  return res.status(401).json({ error: "Teacher login required" });
}

function log(attemptId, event, details = "") {
  db.prepare(
    `INSERT INTO logs (attempt, event, details, at)
     VALUES (?, ?, ?, ?)`
  ).run(
    attemptId,
    event,
    String(details).slice(0, 300),
    now()
  );
}

function publicAttempt(a) {
  return {
    id: a.id,
    code: a.code,
    student: a.student,
    started: a.started,
    submitted: a.submitted,
    status: a.status,
    consent: a.consent,
    result: a.result ? JSON.parse(a.result) : null
  };
}

// --------------------------------------------------
// TEACHER AUTHENTICATION
// --------------------------------------------------

app.get("/api/teacher/me", auth, (req, res) => {
  res.json({ ok: true, username: TEACHER_USERNAME });
});

app.post("/api/teacher/login", async (req, res) => {
  try {
    const username = String(req.body.username || "");
    const password = String(req.body.password || "");

    if (username !== TEACHER_USERNAME) {
      return res.status(401).json({ error: "Incorrect username or password" });
    }

    const validPassword = await bcrypt.compare(
      password,
      TEACHER_PASSWORD_HASH
    );

    if (!validPassword) {
      return res.status(401).json({ error: "Incorrect username or password" });
    }

    // Create a fresh session after successful authentication.
    req.session.regenerate((err) => {
      if (err) {
        console.error("Session regeneration error:", err);
        return res.status(500).json({ error: "Could not create login session" });
      }

      req.session.teacher = true;
      req.session.teacherUsername = TEACHER_USERNAME;

      // Wait until the session is stored before returning success.
      req.session.save((saveErr) => {
        if (saveErr) {
          console.error("Session save error:", saveErr);
          return res.status(500).json({ error: "Could not save login session" });
        }

        return res.json({ ok: true });
      });
    });
  } catch (err) {
    console.error("Login error:", err);
    return res.status(500).json({ error: "Login failed due to a server error" });
  }
});

app.post("/api/teacher/logout", auth, (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("Logout error:", err);
      return res.status(500).json({ error: "Could not log out" });
    }

    res.clearCookie("connect.sid", {
      httpOnly: true,
      sameSite: "lax",
      secure: "auto",
      path: "/"
    });

    return res.json({ ok: true });
  });
});

// --------------------------------------------------
// EXAM CODES AND TEACHER REPORTS
// --------------------------------------------------

app.post("/api/teacher/codes", auth, (req, res) => {
  try {
    const code = crypto.randomBytes(4).toString("hex").toUpperCase();
    const student = String(req.body.student || "Student").slice(0, 80);
    const expires = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

    db.prepare(
      "INSERT INTO codes (code, student, expires) VALUES (?, ?, ?)"
    ).run(code, student, expires);

    return res.json({ code, student, expires });
  } catch (err) {
    console.error("Code generation error:", err);
    return res.status(500).json({ error: "Could not generate exam code" });
  }
});

app.get("/api/teacher/attempts", auth, (req, res) => {
  try {
    const attempts = db
      .prepare("SELECT * FROM attempts ORDER BY id DESC LIMIT 100")
      .all()
      .map(publicAttempt);

    return res.json(attempts);
  } catch (err) {
    console.error("Attempts error:", err);
    return res.status(500).json({ error: "Could not load attempts" });
  }
});

app.get("/api/teacher/attempts/:id", auth, (req, res) => {
  const id = Number(req.params.id);

  if (!Number.isInteger(id) || id < 1) {
    return res.status(400).json({ error: "Invalid attempt ID" });
  }

  const attempt = db.prepare("SELECT * FROM attempts WHERE id = ?").get(id);

  if (!attempt) {
    return res.status(404).json({ error: "Attempt not found" });
  }

  const logs = db
    .prepare(
      "SELECT event, details, at FROM logs WHERE attempt = ? ORDER BY id"
    )
    .all(attempt.id);

  return res.json({
    ...publicAttempt(attempt),
    answers: JSON.parse(attempt.answers || "{}"),
    logs
  });
});

// --------------------------------------------------
// STUDENT EXAM
// --------------------------------------------------

app.post("/api/student/start", (req, res) => {
  try {
    const code = String(req.body.code || "").trim().toUpperCase();

    const codeRow = db
      .prepare("SELECT * FROM codes WHERE code = ?")
      .get(code);

    if (
      !codeRow ||
      codeRow.used ||
      Date.now() > Date.parse(codeRow.expires)
    ) {
      return res.status(400).json({
        error: "Invalid, expired, or used exam code"
      });
    }

    const insert = db.prepare(
      `INSERT INTO attempts (code, student, started, status)
       VALUES (?, ?, ?, 'in_progress')`
    ).run(code, codeRow.student, now());

    // Mark this one-use code as used.
    db.prepare("UPDATE codes SET used = 1 WHERE code = ?").run(code);

    const attemptId = Number(insert.lastInsertRowid);
    log(attemptId, "exam_started", "Exam opened");

    const safeQuestions = questions.map(
      ({ id, difficulty, topic, question, options }) => ({
        id,
        difficulty,
        topic,
        question,
        options
      })
    );

    return res.json({
      id: attemptId,
      student: codeRow.student,
      questions: safeQuestions
    });
  } catch (err) {
    console.error("Student start error:", err);
    return res.status(500).json({ error: "Could not start exam" });
  }
});

app.post("/api/student/:id/consent", (req, res) => {
  const attemptId = Number(req.params.id);

  const attempt = db
    .prepare("SELECT * FROM attempts WHERE id = ? AND status = 'in_progress'")
    .get(attemptId);

  if (!attempt) {
    return res.status(404).json({ error: "Exam not active" });
  }

  if (req.body.consent !== true) {
    return res.status(400).json({ error: "Consent is required" });
  }

  db.prepare("UPDATE attempts SET consent = ? WHERE id = ?")
    .run(now(), attemptId);

  log(
    attemptId,
    "camera_consent",
    "Student agreed to live camera monitoring and activity logging"
  );

  return res.json({ ok: true });
});

app.post("/api/student/:id/answer", (req, res) => {
  const attemptId = Number(req.params.id);

  const attempt = db
    .prepare("SELECT * FROM attempts WHERE id = ? AND status = 'in_progress'")
    .get(attemptId);

  if (!attempt) {
    return res.status(404).json({ error: "Exam not active" });
  }

  const questionId = Number(req.body.questionId);
  const answer = req.body.answer;

  if (!questions.some((q) => q.id === questionId)) {
    return res.status(400).json({ error: "Invalid question ID" });
  }

  const answers = JSON.parse(attempt.answers || "{}");

  if (answer === null || answer === undefined) {
    delete answers[questionId];
  } else if (
    Number.isInteger(answer) &&
    answer >= 0 &&
    answer < questions.find((q) => q.id === questionId).options.length
  ) {
    answers[questionId] = answer;
  } else {
    return res.status(400).json({ error: "Invalid answer option" });
  }

  db.prepare("UPDATE attempts SET answers = ? WHERE id = ?")
    .run(JSON.stringify(answers), attemptId);

  return res.json({ ok: true });
});

app.post("/api/student/:id/log", (req, res) => {
  const attemptId = Number(req.params.id);

  const attempt = db
    .prepare("SELECT status FROM attempts WHERE id = ?")
    .get(attemptId);

  if (!attempt || attempt.status !== "in_progress") {
    return res.status(404).json({ error: "Exam inactive" });
  }

  const allowedEvents = [
    "camera_started",
    "camera_stopped",
    "visibility_hidden",
    "visibility_visible",
    "fullscreen_entered",
    "fullscreen_exited",
    "connection_lost",
    "connection_restored",
    "exam_submitted"
  ];

  if (!allowedEvents.includes(req.body.event)) {
    return res.status(400).json({ error: "Unsupported event" });
  }

  log(attemptId, req.body.event, req.body.details || "");
  return res.json({ ok: true });
});

app.post("/api/student/:id/submit", (req, res) => {
  const attemptId = Number(req.params.id);

  const attempt = db
    .prepare("SELECT * FROM attempts WHERE id = ? AND status = 'in_progress'")
    .get(attemptId);

  if (!attempt) {
    return res.status(404).json({ error: "Exam inactive or already submitted" });
  }

  const answers = JSON.parse(attempt.answers || "{}");
  const stats = {};

  let correct = 0;
  let wrong = 0;
  let unanswered = 0;

  for (const question of questions) {
    const topic = question.topic || "Other";

    if (!stats[topic]) {
      stats[topic] = {
        total: 0,
        correct: 0,
        wrong: 0,
        unanswered: 0
      };
    }

    const topicStats = stats[topic];
    topicStats.total++;

    if (answers[question.id] === undefined) {
      unanswered++;
      topicStats.unanswered++;
    } else if (answers[question.id] === question.answer) {
      correct++;
      topicStats.correct++;
    } else {
      wrong++;
      topicStats.wrong++;
    }
  }

  const result = {
    total: questions.length,
    correct,
    wrong,
    unanswered,
    percentage: questions.length
      ? Math.round((correct / questions.length) * 10000) / 100
      : 0,
    stats,
    review: questions.map((question) => ({
      ...question,
      chosen: answers[question.id] ?? null
    }))
  };

  db.prepare(
    `UPDATE attempts
     SET submitted = ?, result = ?, status = 'submitted'
     WHERE id = ?`
  ).run(now(), JSON.stringify(result), attemptId);

  log(attemptId, "exam_submitted", `${correct}/${questions.length}`);

  return res.json(result);
});

// --------------------------------------------------
// WEBRTC CAMERA SIGNALING
// --------------------------------------------------

// This starter signaling implementation groups peers by attempt.
// It does not record video. Student consent and browser camera
// permission are required by the student page.
io.on("connection", (socket) => {
  socket.on("join-monitor", (data) => {
    if (
      !data ||
      !data.attemptId ||
      !["teacher", "student"].includes(data.role)
    ) {
      return;
    }

    const attemptId = Number(data.attemptId);

    if (!Number.isInteger(attemptId) || attemptId < 1) {
      return;
    }

    socket.join(`exam-${attemptId}`);
    socket.data.role = data.role;
    socket.data.attemptId = attemptId;

    socket.to(`exam-${attemptId}`).emit("peer-ready", {
      role: data.role
    });
  });

  socket.on("signal", (payload) => {
    if (!payload || !socket.data.attemptId) return;

    if (!["offer", "answer", "ice"].includes(payload.kind)) {
      return;
    }

    socket.to(`exam-${socket.data.attemptId}`).emit("signal", {
      kind: payload.kind,
      data: payload.data,
      from: socket.data.role
    });
  });
});

// --------------------------------------------------
// SERVER START
// --------------------------------------------------

server.listen(PORT, () => {
  console.log(`Listening on ${PORT}`);
});
