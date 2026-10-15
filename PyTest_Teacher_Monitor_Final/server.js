
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
const multer = require("multer");
const pdfParse = require("pdf-parse");
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
  console.error("Set SESSION_SECRET to a random secret of at least 32 characters.");
  process.exit(1);
}

if (!TEACHER_PASSWORD_HASH) {
  console.error("Set TEACHER_PASSWORD_HASH in your hosting environment.");
  process.exit(1);
}

app.set("trust proxy", 1);

const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");

db.exec(`
CREATE TABLE IF NOT EXISTS codes (
  code TEXT PRIMARY KEY,
  student TEXT,
  expires TEXT,
  used INTEGER DEFAULT 0,
  exam_json TEXT,
  duration_minutes INTEGER DEFAULT 60
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
  consent TEXT,
  duration_minutes INTEGER DEFAULT 60,
  monitor_token TEXT
);

CREATE TABLE IF NOT EXISTS logs (
  id INTEGER PRIMARY KEY,
  attempt INTEGER,
  event TEXT,
  details TEXT,
  at TEXT
);
`);

function addColumnIfMissing(table, column, definition) {
  const columns = db
    .prepare(`PRAGMA table_info(${table})`)
    .all()
    .map(x => x.name);

  if (!columns.includes(column)) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
  }
}

addColumnIfMissing("codes", "exam_json", "TEXT");
addColumnIfMissing("codes", "duration_minutes", "INTEGER DEFAULT 60");
addColumnIfMissing("attempts", "duration_minutes", "INTEGER DEFAULT 60");
addColumnIfMissing("attempts", "monitor_token", "TEXT");

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "1mb" }));

const sessionMiddleware = session({
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
});

app.use(sessionMiddleware);
io.engine.use(sessionMiddleware);
app.use(express.static(path.join(__dirname, "public")));

const defaultQuestions = require("./questions.json");
const now = () => new Date().toISOString();

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 12 * 1024 * 1024,
    files: 1
  },
  fileFilter: (req, file, cb) => {
    if (
      file.mimetype === "application/pdf" ||
      file.originalname.toLowerCase().endsWith(".pdf")
    ) {
      cb(null, true);
    } else {
      cb(new Error("Please upload a PDF file."));
    }
  }
});

function auth(req, res, next) {
  if (req.session && req.session.teacher === true) {
    return next();
  }

  return res.status(401).json({
    error: "Teacher login required"
  });
}

function log(attemptId, event, details = "") {
  db.prepare(
    "INSERT INTO logs (attempt,event,details,at) VALUES (?,?,?,?)"
  ).run(attemptId, event, String(details).slice(0, 300), now());
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
    duration_minutes: a.duration_minutes,
    result: a.result ? JSON.parse(a.result) : null
  };
}

function cleanQuestion(q, index) {
  const options = Array.isArray(q.options)
    ? q.options.map(x => String(x).trim())
    : [];

  const answer = Number(q.answer);

  if (
    !q.question ||
    options.length < 2 ||
    !Number.isInteger(answer) ||
    answer < 0 ||
    answer >= options.length
  ) {
    return null;
  }

  return {
    id: index + 1,
    topic: String(q.topic || "PDF Import").slice(0, 100),
    difficulty: String(q.difficulty || "Medium").slice(0, 30),
    question: String(q.question).trim(),
    options,
    answer,
    explanation: String(q.explanation || "")
  };
}

/*
Supported selectable-text PDF layout:

Q1. [Low] What is Python?
A) Option one
B) Option two
C) Option three
D) Option four
Answer: A (Low)

Scanned PDFs require OCR.
*/

function parseQuestionsFromPdfText(rawText) {
  const text = String(rawText || "")
    .replace(/\r/g, "\n")
    .replace(/[\u00a0\u2007\u202f]/g, " ")
    .replace(/[ \t]+/g, " ")
    .replace(/\n{3,}/g, "\n\n");

  // Support numbered answer keys at the end of a PDF.
  const answerKey = new Map();

  const keySection = text.match(
    /(?:answer\s*key|answers\s*key|correct\s*answers)\s*[:\-]?([\s\S]*)/i
  );

  if (keySection) {
    const keyText = keySection[1];

    for (const m of keyText.matchAll(
      /(?:^|[\s,;|])(?:Q\s*)?(\d{1,3})\s*[.)\-:]?\s*([A-D])\b/gi
    )) {
      answerKey.set(
        Number(m[1]),
        m[2].toUpperCase().charCodeAt(0) - 65
      );
    }
  }

  // Split the PDF text into numbered questions.
  const startRegex =
    /(?:^|\n)\s*(?:Q(?:uestion)?\s*)?(\d{1,3})\s*[.)]\s*/gim;

  const starts = [...text.matchAll(startRegex)];
  const chunks = [];

  for (let i = 0; i < starts.length; i++) {
    const match = starts[i];

    const start =
      match.index + (match[0].startsWith("\n") ? 1 : 0);

    const end =
      i + 1 < starts.length
        ? starts[i + 1].index
        : text.length;

    chunks.push({
      number: Number(match[1]),
      text: text.slice(start, end).trim()
    });
  }

  const questions = [];

  for (const item of chunks) {
    let chunk = item.text;

    chunk = chunk.replace(
      /^\s*(?:Q(?:uestion)?\s*)?\d{1,3}\s*[.)]\s*/i,
      ""
    );

    const difficultyMatch = chunk.match(
      /^\s*\[(Low|Medium|Hard)\]\s*/i
    );

    const difficulty = difficultyMatch
      ? difficultyMatch[1]
      : "Medium";

    chunk = chunk.replace(
      /^\s*\[(?:Low|Medium|Hard)\]\s*/i,
      ""
    );

    // Remove answer-key pages/sections from the question body.
    chunk = chunk.replace(
      /\n\s*(?:answer\s*key|answers\s*key|correct\s*answers)\b[\s\S]*$/i,
      ""
    );

    const answerMatch =
      chunk.match(
        /(?:correct\s+)?answer\s*[:\-=]\s*([A-D]|[1-4])\b/i
      ) ||
      chunk.match(
        /\bAns\.?\s*[:\-=]\s*([A-D]|[1-4])\b/i
      );

    // Accept option labels A), A., A:, and (A).
    const optionRegex =
      /(?:^|\n|\s{2,})\(?([A-D])\)?\s*[.):]\s+/gim;

    const optionMatches = [...chunk.matchAll(optionRegex)];

    if (optionMatches.length < 2) continue;

    const unique = [];
    const seen = new Set();

    for (const match of optionMatches) {
      const letter = match[1].toUpperCase();

      if (!seen.has(letter)) {
        seen.add(letter);
        unique.push(match);
      }

      if (unique.length === 4) break;
    }

    if (unique.length < 2) continue;

    const first = unique[0];

    let questionText = chunk
      .slice(0, first.index)
      .trim();

    questionText = questionText
      .replace(/^\s*(?:Q(?:uestion)?\s*)?\d{1,3}\s*[.)]\s*/i, "")
      .trim();

    const options = [];

    for (let i = 0; i < unique.length; i++) {
      const match = unique[i];

      const labelPosition = match[0].search(
        /\(?[A-D]\)?\s*[.):]/i
      );

      const valueStart =
        match.index +
        labelPosition +
        match[0].slice(labelPosition).length;

      const next = unique[i + 1];
      const valueEnd = next ? next.index : chunk.length;

      let value = chunk.slice(valueStart, valueEnd).trim();

      value = value.replace(
        /\n?\s*(?:correct\s+)?answer\s*[:\-=].*$/is,
        ""
      ).trim();

      value = value.replace(
        /\n?\s*(?:explanation|solution)\s*[:\-=].*$/is,
        ""
      ).trim();

      if (value) options.push(value);
    }

    let answer = -1;

    if (answerMatch) {
      const answerValue = answerMatch[1].toUpperCase();

      answer = /^[A-D]$/.test(answerValue)
        ? answerValue.charCodeAt(0) - 65
        : Number(answerValue) - 1;
    } else if (answerKey.has(item.number)) {
      answer = answerKey.get(item.number);
    }

    if (
      questionText &&
      options.length >= 2 &&
      answer >= 0 &&
      answer < options.length
    ) {
      questions.push({
        question: questionText,
        options: options.slice(0, 4),
        answer,
        topic: "PDF Import",
        difficulty
      });
    }
  }

  return questions
    .map((q, i) => cleanQuestion(q, i))
    .filter(Boolean);
}

// --------------------------------------------------
// HEALTH AND TEACHER LOGIN
// --------------------------------------------------

app.get("/api/health", (req, res) => {
  res.json({ ok: true });
});

app.get("/api/teacher/me", auth, (req, res) => {
  res.json({
    ok: true,
    username: TEACHER_USERNAME
  });
});

app.post("/api/teacher/login", async (req, res) => {
  try {
    if (
      String(req.body.username || "") !== TEACHER_USERNAME ||
      !await bcrypt.compare(
        String(req.body.password || ""),
        TEACHER_PASSWORD_HASH
      )
    ) {
      return res.status(401).json({
        error: "Incorrect username or password"
      });
    }

    req.session.regenerate(err => {
      if (err) {
        return res.status(500).json({
          error: "Could not create login session"
        });
      }

      req.session.teacher = true;
      req.session.teacherUsername = TEACHER_USERNAME;

      req.session.save(saveErr => {
        if (saveErr) {
          return res.status(500).json({
            error: "Could not save login session"
          });
        }

        res.json({ ok: true });
      });
    });
  } catch (e) {
    console.error(e);

    res.status(500).json({
      error: "Login failed"
    });
  }
});

app.post("/api/teacher/logout", auth, (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.status(500).json({
        error: "Could not log out"
      });
    }

    res.clearCookie("connect.sid", {
      httpOnly: true,
      sameSite: "lax",
      secure: "auto",
      path: "/"
    });

    res.json({ ok: true });
  });
});

// --------------------------------------------------
// PDF UPLOAD AND QUESTION SET
// --------------------------------------------------

app.post(
  "/api/teacher/upload-pdf",
  auth,
  upload.single("pdf"),
  async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({
          error: "Choose a PDF file first."
        });
      }

      const parsed = await pdfParse(req.file.buffer);

      const questions = parseQuestionsFromPdfText(
        parsed.text || ""
      );

      if (!questions.length) {
        return res.status(422).json({
          error:
            "No complete MCQs with answers were detected. " +
            "Use a selectable-text PDF with numbered questions, " +
            "A-D options, and an inline answer or numbered answer key."
        });
      }

      req.session.importedQuestions = questions;

      req.session.save(err => {
        if (err) {
          return res.status(500).json({
            error: "Could not save imported questions."
          });
        }

        res.json({
          count: questions.length,
          questions: questions.map(q => ({
            id: q.id,
            topic: q.topic,
            difficulty: q.difficulty,
            question: q.question,
            options: q.options,
            answer: q.answer
          }))
        });
      });
    } catch (e) {
      console.error("PDF import:", e);

      res.status(500).json({
        error:
          "Could not read this PDF. It may be scanned or password-protected."
      });
    }
  }
);

app.post("/api/teacher/use-default-questions", auth, (req, res) => {
  req.session.importedQuestions = defaultQuestions
    .map((q, i) => cleanQuestion(q, i))
    .filter(Boolean);

  req.session.save(err => {
    if (err) {
      return res.status(500).json({
        error: "Could not save question set."
      });
    }

    res.json({
      count: req.session.importedQuestions.length
    });
  });
});

app.get("/api/teacher/question-set", auth, (req, res) => {
  const questions = req.session.importedQuestions || [];

  res.json({
    count: questions.length,
    questions: questions.map(q => ({
      id: q.id,
      topic: q.topic,
      question: q.question,
      options: q.options,
      answer: q.answer
    }))
  });
});

// --------------------------------------------------
// CREATE EXAM CODE
// --------------------------------------------------

app.post("/api/teacher/codes", auth, (req, res) => {
  try {
    const student = String(req.body.student || "Student").slice(0, 80);
    const duration = Number(req.body.durationMinutes || 60);

    if (!Number.isInteger(duration) || duration < 1 || duration > 300) {
      return res.status(400).json({
        error: "Duration must be 1 to 300 minutes."
      });
    }

    // Do not silently load sample questions after a failed PDF import.
    const sourceQuestions = req.session.importedQuestions;

    if (!Array.isArray(sourceQuestions) || !sourceQuestions.length) {
      return res.status(400).json({
        error:
          "No questions imported. Upload a PDF or explicitly choose sample questions."
      });
    }

    const requestedCount = Number(
      req.body.questionCount || sourceQuestions.length
    );

    if (
      !Number.isInteger(requestedCount) ||
      requestedCount < 1 ||
      requestedCount > sourceQuestions.length
    ) {
      return res.status(400).json({
        error:
          `Question count must be between 1 and ${sourceQuestions.length}.`
      });
    }

    const selected = sourceQuestions
      .slice(0, requestedCount)
      .map((q, i) => ({ ...q, id: i + 1 }));

    const code = crypto.randomBytes(4).toString("hex").toUpperCase();

    const expires = new Date(
      Date.now() + 24 * 60 * 60 * 1000
    ).toISOString();

    db.prepare(
      "INSERT INTO codes (code,student,expires,exam_json,duration_minutes) VALUES (?,?,?,?,?)"
    ).run(
      code,
      student,
      expires,
      JSON.stringify(selected),
      duration
    );

    res.json({
      code,
      student,
      expires,
      durationMinutes: duration,
      questionCount: selected.length
    });
  } catch (e) {
    console.error("Create code:", e);

    res.status(500).json({
      error: "Could not create exam code."
    });
  }
});

// --------------------------------------------------
// TEACHER ATTEMPTS AND RESULTS
// --------------------------------------------------

app.get("/api/teacher/attempts", auth, (req, res) => {
  try {
    const attempts = db
      .prepare("SELECT * FROM attempts ORDER BY id DESC LIMIT 100")
      .all()
      .map(publicAttempt);

    res.json(attempts);
  } catch (e) {
    console.error(e);

    res.status(500).json({
      error: "Could not load attempts"
    });
  }
});

app.get("/api/teacher/attempts/:id", auth, (req, res) => {
  const attempt = db
    .prepare("SELECT * FROM attempts WHERE id=?")
    .get(Number(req.params.id));

  if (!attempt) {
    return res.status(404).json({
      error: "Attempt not found"
    });
  }

  const logs = db
    .prepare("SELECT event,details,at FROM logs WHERE attempt=? ORDER BY id")
    .all(attempt.id);

  res.json({
    ...publicAttempt(attempt),
    answers: JSON.parse(attempt.answers || "{}"),
    logs
  });
});

// --------------------------------------------------
// STUDENT START EXAM
// --------------------------------------------------

app.post("/api/student/start", (req, res) => {
  try {
    const code = String(req.body.code || "").trim().toUpperCase();

    const row = db
      .prepare("SELECT * FROM codes WHERE code=?")
      .get(code);

    if (!row || row.used || Date.now() > Date.parse(row.expires)) {
      return res.status(400).json({
        error: "Invalid, expired, or used exam code"
      });
    }

    const examQuestions = row.exam_json
      ? JSON.parse(row.exam_json)
      : defaultQuestions;

    const duration = Number(row.duration_minutes || 60);

    // Unique token authorizes the student monitoring socket for this attempt.
    const monitorToken = crypto.randomBytes(24).toString("hex");

    const insert = db.prepare(
      "INSERT INTO attempts (code,student,started,status,duration_minutes,monitor_token) VALUES (?,?,?,'in_progress',?,?)"
    ).run(
      code,
      row.student,
      now(),
      duration,
      monitorToken
    );

    db.prepare("UPDATE codes SET used=1 WHERE code=?").run(code);

    const attemptId = Number(insert.lastInsertRowid);

    log(attemptId, "exam_started", "Exam opened");

    res.json({
      id: attemptId,
      monitorToken,
      student: row.student,
      durationMinutes: duration,
      questions: examQuestions.map(
        ({ id, difficulty, topic, question, options }) => ({
          id,
          difficulty,
          topic,
          question,
          options
        })
      )
    });
  } catch (e) {
    console.error(e);

    res.status(500).json({
      error: "Could not start exam"
    });
  }
});

// --------------------------------------------------
// STUDENT CONSENT
// --------------------------------------------------

app.post("/api/student/:id/consent", (req, res) => {
  const id = Number(req.params.id);

  const attempt = db
    .prepare("SELECT * FROM attempts WHERE id=? AND status='in_progress'")
    .get(id);

  if (!attempt) {
    return res.status(404).json({
      error: "Exam not active"
    });
  }

  if (req.body.consent !== true) {
    return res.status(400).json({
      error: "Consent is required"
    });
  }

  db.prepare("UPDATE attempts SET consent=? WHERE id=?")
    .run(now(), id);

  log(
    id,
    "camera_consent",
    "Student agreed to live camera monitoring and activity logging"
  );

  res.json({ ok: true });
});

// --------------------------------------------------
// SAVE STUDENT ANSWER
// --------------------------------------------------

app.post("/api/student/:id/answer", (req, res) => {
  const id = Number(req.params.id);

  const attempt = db
    .prepare("SELECT * FROM attempts WHERE id=? AND status='in_progress'")
    .get(id);

  if (!attempt) {
    return res.status(404).json({
      error: "Exam not active"
    });
  }

  const questions = (() => {
    const row = db
      .prepare("SELECT exam_json FROM codes WHERE code=?")
      .get(attempt.code);

    return row && row.exam_json
      ? JSON.parse(row.exam_json)
      : defaultQuestions;
  })();

  const qid = Number(req.body.questionId);
  const question = questions.find(q => q.id === qid);

  if (!question) {
    return res.status(400).json({
      error: "Invalid question ID"
    });
  }

  const answers = JSON.parse(attempt.answers || "{}");
  const answer = req.body.answer;

  if (answer === null || answer === undefined) {
    delete answers[qid];
  } else if (
    Number.isInteger(answer) &&
    answer >= 0 &&
    answer < question.options.length
  ) {
    answers[qid] = answer;
  } else {
    return res.status(400).json({
      error: "Invalid answer option"
    });
  }

  db.prepare("UPDATE attempts SET answers=? WHERE id=?")
    .run(JSON.stringify(answers), id);

  res.json({ ok: true });
});

// --------------------------------------------------
// STUDENT ACTIVITY LOGS
// --------------------------------------------------

app.post("/api/student/:id/log", (req, res) => {
  const id = Number(req.params.id);

  const attempt = db
    .prepare("SELECT status FROM attempts WHERE id=?")
    .get(id);

  if (!attempt || attempt.status !== "in_progress") {
    return res.status(404).json({
      error: "Exam inactive"
    });
  }

  const allowed = [
    "exam_started",
    "camera_consent",
    "camera_started",
    "camera_stopped",
    "visibility_hidden",
    "visibility_visible",
    "fullscreen_entered",
    "fullscreen_exited",
    "fullscreen_failed",
    "connection_lost",
    "connection_restored",
    "exam_submitted",
    "copy_attempt",
    "paste_attempt",
    "cut_attempt",
    "right_click",
    "copy_shortcut",
    "paste_shortcut",
    "cut_shortcut",
    "print_shortcut",
    "save_shortcut"
  ];

  if (!allowed.includes(req.body.event)) {
    return res.status(400).json({
      error: "Unsupported event"
    });
  }

  log(id, req.body.event, req.body.details || "");

  res.json({ ok: true });
});

// --------------------------------------------------
// SUBMIT EXAM
// --------------------------------------------------

app.post("/api/student/:id/submit", (req, res) => {
  const id = Number(req.params.id);

  const attempt = db
    .prepare("SELECT * FROM attempts WHERE id=? AND status='in_progress'")
    .get(id);

  if (!attempt) {
    return res.status(404).json({
      error: "Exam inactive or already submitted"
    });
  }

  const codeRow = db
    .prepare("SELECT exam_json FROM codes WHERE code=?")
    .get(attempt.code);

  const questions = codeRow && codeRow.exam_json
    ? JSON.parse(codeRow.exam_json)
    : defaultQuestions;

  const answers = JSON.parse(attempt.answers || "{}");
  const stats = {};

  let correct = 0;
  let wrong = 0;
  let unanswered = 0;

  for (const q of questions) {
    const topic = q.topic || "Other";

    if (!stats[topic]) {
      stats[topic] = {
        total: 0,
        correct: 0,
        wrong: 0,
        unanswered: 0
      };
    }

    stats[topic].total++;

    if (answers[q.id] === undefined) {
      unanswered++;
      stats[topic].unanswered++;
    } else if (answers[q.id] === q.answer) {
      correct++;
      stats[topic].correct++;
    } else {
      wrong++;
      stats[topic].wrong++;
    }
  }

  const result = {
    total: questions.length,
    correct,
    wrong,
    unanswered,
    percentage: questions.length
      ? Math.round(correct / questions.length * 10000) / 100
      : 0,
    stats,
    review: questions.map(q => ({
      ...q,
      chosen: answers[q.id] ?? null
    }))
  };

  db.prepare(
    "UPDATE attempts SET submitted=?,result=?,status='submitted' WHERE id=?"
  ).run(
    now(),
    JSON.stringify(result),
    id
  );

  log(id, "exam_submitted", `${correct}/${questions.length}`);

  res.json(result);
});

// --------------------------------------------------
// WEBRTC SIGNALLING
// STUN-only: no TURN relay server is configured here.
// --------------------------------------------------

io.on("connection", socket => {
  socket.on("join-monitor", async data => {
    try {
      if (
        !data ||
        !data.attemptId ||
        !["teacher", "student"].includes(data.role)
      ) {
        return;
      }

      const id = Number(data.attemptId);

      if (!Number.isInteger(id) || id < 1) return;

      const attempt = db
        .prepare(
          "SELECT id,status,consent,monitor_token FROM attempts WHERE id=?"
        )
        .get(id);

      if (!attempt) {
        return socket.emit("monitor-error", {
          message: "Attempt not found."
        });
      }

      // Only an authenticated teacher can monitor this attempt.
      if (data.role === "teacher") {
        if (
          !socket.request.session ||
          socket.request.session.teacher !== true
        ) {
          return socket.emit("monitor-error", {
            message: "Teacher login required for camera monitoring."
          });
        }
      } else {
        // Student monitoring requires consent and the attempt token.
        if (
          attempt.status !== "in_progress" ||
          !attempt.consent ||
          typeof data.monitorToken !== "string" ||
          data.monitorToken !== attempt.monitor_token
        ) {
          return socket.emit("monitor-error", {
            message:
              "Student camera session is not authorized or consent is missing."
          });
        }
      }

      const room = `exam-${id}`;

      socket.data.role = data.role;
      socket.data.attemptId = id;

      await socket.join(room);

      // Notify peers even when the student or teacher joins first.
      const members = await io.in(room).fetchSockets();

      for (const member of members) {
        const peer = members.find(other =>
          other.id !== member.id &&
          other.data.attemptId === id &&
          other.data.role &&
          other.data.role !== member.data.role
        );

        if (peer) {
          member.emit("peer-ready", {
            role: peer.data.role
          });
        }
      }
    } catch (error) {
      console.error("join-monitor error:", error);

      socket.emit("monitor-error", {
        message: "Could not join camera monitoring room."
      });
    }
  });

  socket.on("signal", payload => {
    const id = socket.data.attemptId;
    const role = socket.data.role;

    if (
      !id ||
      !["teacher", "student"].includes(role) ||
      !payload ||
      !["offer", "answer", "ice"].includes(payload.kind)
    ) {
      return;
    }

    socket.to(`exam-${id}`).emit("signal", {
      kind: payload.kind,
      data: payload.data,
      from: role
    });
  });

  socket.on("disconnect", () => {
    if (socket.data.attemptId) {
      socket.to(`exam-${socket.data.attemptId}`).emit("peer-left", {
        role: socket.data.role || "peer"
      });
    }
  });
});

// --------------------------------------------------
// ERROR HANDLER AND START SERVER
// --------------------------------------------------

app.use((err, req, res, next) => {
  console.error(err);

  res.status(400).json({
    error: err.message || "Request failed"
  });
});

server.listen(PORT, () => {
  console.log(`PyTest Arena listening on ${PORT}`);
});
