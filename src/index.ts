import bcrypt from "bcrypt";
import cors from "cors";
import express from "express";
import jwt from "jsonwebtoken";
import { pool } from "./db";

const app = express();
console.log("CORS_ORIGINS=", process.env.CORS_ORIGINS);
const envOrigins = (process.env.CORS_ORIGINS ?? "")
  .split(",")
  .map((value) => value.trim())
  .filter((value) => value.length > 0);
const allowedOrigins = new Set(
  envOrigins.length > 0
    ? envOrigins
    : [
        "http://localhost:3000",
        "http://localhost:3001",
        "https://learning-app-web-tan.vercel.app",
      ],
); // default to local dev when env is empty
const frontendUrl = process.env.FRONTEND_URL;
if (frontendUrl && !allowedOrigins.has(frontendUrl)) {
  allowedOrigins.add(frontendUrl);
}
const corsOptions: cors.CorsOptions = {
  origin: (origin, callback) => {
    if (!origin) {
      return callback(null, true);
    }
    if (allowedOrigins.has(origin)) {
      return callback(null, true);
    }
    return callback(new Error("Not allowed by CORS"));
  },
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: true,
};

app.use(cors(corsOptions));
app.use(express.json());

app.get("/health", (_req, res) => {
  res.json({ status: "ok" });
});

type AuthenticatedRequest = express.Request & { userId: string };

const isUuid = (value: string): boolean =>
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(
    value,
  );

const authMiddleware: express.RequestHandler = (req, res, next) => {
  const authHeader = req.header("authorization");
  const token = authHeader?.startsWith("Bearer ") ? authHeader.slice(7) : null;

  if (!token) {
    return res.status(401).json({ error: "unauthorized" });
  }

  const jwtSecret = process.env.JWT_SECRET;
  if (!jwtSecret) {
    return res.status(500).json({ error: "JWT_SECRET is not set" });
  }

  try {
    const payload = jwt.verify(token, jwtSecret);
    if (
      typeof payload !== "object" ||
      payload === null ||
      !("user_id" in payload) ||
      typeof payload.user_id !== "string"
    ) {
      return res.status(401).json({ error: "unauthorized" });
    }

    (req as AuthenticatedRequest).userId = payload.user_id;
    return next();
  } catch (error) {
    return res.status(401).json({ error: "unauthorized" });
  }
};

app.get("/api/v1/me", authMiddleware, async (req, res) => {
  const { userId } = req as AuthenticatedRequest;

  try {
    const result = await pool.query(
      "SELECT id, email, display_name, avatar_url, provider FROM users WHERE id = $1",
      [userId],
    );
    const user = result.rows[0];
    if (!user) {
      return res.status(401).json({ error: "unauthorized" });
    }
    return res.json({ user });
  } catch (error) {
    console.error("me failed", error);
    return res.status(500).json({ error: "internal server error" });
  }
});

const fetchFn = (globalThis as { fetch?: (input: string, init?: any) => Promise<any> })
  .fetch;
const fetchJson = async (
  url: string,
  options: { method?: string; headers?: Record<string, string>; body?: string },
): Promise<any> => {
  if (!fetchFn) {
    throw new Error("fetch is not available");
  }
  const response = await fetchFn(url, options);
  if (!response.ok) {
    const text = await response.text();
    throw new Error(`oauth request failed: ${response.status} ${text}`);
  }
  return response.json();
};

const getRedirectBaseUrl = (): string | null => {
  return process.env.OAUTH_REDIRECT_BASE_URL ?? null;
};

const buildFrontendRedirect = (token: string): string | null => {
  if (!frontendUrl) {
    return null;
  }
  const base = frontendUrl.replace(/\/$/, "");
  return `${base}/login/callback?token=${encodeURIComponent(token)}`;
};

const createOauthState = (provider: string): string => {
  const jwtSecret = process.env.JWT_SECRET;
  if (!jwtSecret) {
    throw new Error("JWT_SECRET is not set");
  }
  return jwt.sign({ provider, typ: "oauth_state" }, jwtSecret, {
    expiresIn: "10m",
  });
};

const verifyOauthState = (provider: string, state: string): string | null => {
  const jwtSecret = process.env.JWT_SECRET;
  if (!jwtSecret) {
    throw new Error("JWT_SECRET is not set");
  }
  try {
    const payload = jwt.verify(state, jwtSecret);
    if (typeof payload !== "object" || payload === null) {
      return "payload_invalid";
    }
    if (payload.typ !== "oauth_state") {
      return "typ_mismatch";
    }
    if (payload.provider !== provider) {
      return "provider_mismatch";
    }
    return null;
  } catch (error) {
    if (
      typeof error === "object" &&
      error !== null &&
      "name" in error &&
      (error as { name?: string }).name === "TokenExpiredError"
    ) {
      return "expired";
    }
    return "signature_mismatch";
  }
};

app.post("/api/v1/auth/signup", async (req, res) => {
  const { email, password } = req.body ?? {};

  if (typeof email !== "string" || typeof password !== "string") {
    return res.status(400).json({ error: "email and password are required" });
  }

  const normalizedEmail = email.trim();

  if (!normalizedEmail || !password) {
    return res.status(400).json({ error: "email and password are required" });
  }

  try {
    const passwordHash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      "INSERT INTO users (email, password_hash, provider) VALUES ($1, $2, $3) RETURNING id, email, created_at, updated_at",
      [normalizedEmail, passwordHash, "password"],
    );

    return res.status(201).json({ user: result.rows[0] });
  } catch (error: unknown) {
    if (typeof error === "object" && error !== null && "code" in error) {
      const pgError = error as { code?: string };
      if (pgError.code === "23505") {
        return res.status(409).json({ error: "email already exists" });
      }
    }

    console.error("signup failed", error);
    return res.status(500).json({ error: "internal server error" });
  }
});

app.post("/api/v1/auth/login", async (req, res) => {
  const { email, password } = req.body ?? {};

  if (typeof email !== "string" || typeof password !== "string") {
    return res.status(400).json({ error: "email and password are required" });
  }

  const normalizedEmail = email.trim();

  if (!normalizedEmail || !password) {
    return res.status(400).json({ error: "email and password are required" });
  }

  try {
    const result = await pool.query(
      "SELECT id, email, password_hash FROM users WHERE email = $1",
      [normalizedEmail],
    );
    const user = result.rows[0];

    if (!user) {
      return res.status(401).json({ error: "invalid credentials" });
    }

    if (!user.password_hash) {
      return res.status(401).json({ error: "invalid credentials" });
    }

    const isValid = await bcrypt.compare(password, user.password_hash);
    if (!isValid) {
      return res.status(401).json({ error: "invalid credentials" });
    }

    await pool.query("UPDATE users SET provider = $1 WHERE id = $2", ["password", user.id]);

    const jwtSecret = process.env.JWT_SECRET;
    if (!jwtSecret) {
      return res.status(500).json({ error: "JWT_SECRET is not set" });
    }

    const token = jwt.sign({ user_id: user.id }, jwtSecret);
    return res.json({ token });
  } catch (error) {
    console.error("login failed", error);
    return res.status(500).json({ error: "internal server error" });
  }
});

app.get("/api/v1/auth/oauth/:provider/start", (req, res) => {
  const { provider } = req.params;
  const redirectBaseUrl = getRedirectBaseUrl();

  if (!redirectBaseUrl) {
    return res.status(500).json({ error: "OAUTH_REDIRECT_BASE_URL is not set" });
  }

  if (provider !== "google" && provider !== "github") {
    return res.status(404).json({ error: "not_found" });
  }

  const redirectUri = `${redirectBaseUrl}/api/v1/auth/oauth/${provider}/callback`;
  let state: string;
  try {
    state = createOauthState(provider);
  } catch (error) {
    console.error("oauth state creation failed", error);
    return res.status(500).json({ error: "internal server error" });
  }
  if (provider === "google") {
    const clientId = process.env.GOOGLE_CLIENT_ID;
    if (!clientId) {
      return res.status(500).json({ error: "GOOGLE_CLIENT_ID is not set" });
    }
    const url = new URL("https://accounts.google.com/o/oauth2/v2/auth");
    url.searchParams.set("client_id", clientId);
    url.searchParams.set("redirect_uri", redirectUri);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("scope", "openid email profile");
    url.searchParams.set("state", state);
    return res.redirect(url.toString());
  }

  const clientId = process.env.GITHUB_CLIENT_ID;
  if (!clientId) {
    return res.status(500).json({ error: "GITHUB_CLIENT_ID is not set" });
  }
  const url = new URL("https://github.com/login/oauth/authorize");
  url.searchParams.set("client_id", clientId);
  url.searchParams.set("redirect_uri", redirectUri);
  url.searchParams.set("scope", "user:email");
  url.searchParams.set("state", state);
  return res.redirect(url.toString());
});

app.get("/api/v1/auth/oauth/:provider/callback", async (req, res) => {
  const { provider } = req.params;
  const { code, state } = req.query;

  if (provider !== "google" && provider !== "github") {
    return res.status(404).json({ error: "not_found" });
  }
  if (typeof code !== "string" || !code) {
    return res.status(400).json({ error: "invalid_request" });
  }
  if (typeof state !== "string" || !state) {
    return res.status(400).json({ error: "invalid_request" });
  }
  let stateError: string | null;
  try {
    stateError = verifyOauthState(provider, state);
  } catch (error) {
    console.error("invalid_oauth_state: verification_failed", error);
    return res.status(500).json({ error: "internal server error" });
  }
  if (stateError) {
    console.error(`invalid_oauth_state: ${stateError}`);
    return res.status(400).json({ error: "invalid_request" });
  }

  const redirectBaseUrl = getRedirectBaseUrl();
  if (!redirectBaseUrl) {
    return res.status(500).json({ error: "OAUTH_REDIRECT_BASE_URL is not set" });
  }
  const redirectUri = `${redirectBaseUrl}/api/v1/auth/oauth/${provider}/callback`;

  try {
    let email: string | null = null;
    let displayName: string | null = null;
    let avatarUrl: string | null = null;
    let providerUserId: string | null = null;
    if (provider === "google") {
      const clientId = process.env.GOOGLE_CLIENT_ID;
      const clientSecret = process.env.GOOGLE_CLIENT_SECRET;
      if (!clientId || !clientSecret) {
        return res.status(500).json({ error: "Google OAuth env is not set" });
      }
      const tokenResponse = await fetchJson("https://oauth2.googleapis.com/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          client_id: clientId,
          client_secret: clientSecret,
          code,
          grant_type: "authorization_code",
          redirect_uri: redirectUri,
        }).toString(),
      });
      const accessToken = tokenResponse.access_token;
      if (typeof accessToken !== "string") {
        throw new Error("Google access_token is missing");
      }
      const userInfo = await fetchJson("https://openidconnect.googleapis.com/v1/userinfo", {
        headers: { Authorization: `Bearer ${accessToken}` },
      });
      if (typeof userInfo.email === "string") {
        email = userInfo.email.trim();
      }
      if (typeof userInfo.name === "string" && userInfo.name.trim()) {
        displayName = userInfo.name.trim();
      } else if (typeof userInfo.given_name === "string" && userInfo.given_name.trim()) {
        displayName = userInfo.given_name.trim();
      }
      if (typeof userInfo.picture === "string" && userInfo.picture.trim()) {
        avatarUrl = userInfo.picture.trim();
      }
      if (typeof userInfo.sub === "string" && userInfo.sub.trim()) {
        providerUserId = userInfo.sub.trim();
      }
    } else {
      const clientId = process.env.GITHUB_CLIENT_ID;
      const clientSecret = process.env.GITHUB_CLIENT_SECRET;
      if (!clientId || !clientSecret) {
        return res.status(500).json({ error: "GitHub OAuth env is not set" });
      }
      const tokenResponse = await fetchJson("https://github.com/login/oauth/access_token", {
        method: "POST",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          client_id: clientId,
          client_secret: clientSecret,
          code,
          redirect_uri: redirectUri,
        }).toString(),
      });
      const accessToken = tokenResponse.access_token;
      if (typeof accessToken !== "string") {
        throw new Error("GitHub access_token is missing");
      }
      const userInfo = await fetchJson("https://api.github.com/user", {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          Accept: "application/json",
          "User-Agent": "ts-memo-api",
        },
      });
      if (typeof userInfo.email === "string" && userInfo.email) {
        email = userInfo.email.trim();
      }
      if (typeof userInfo.name === "string" && userInfo.name.trim()) {
        displayName = userInfo.name.trim();
      } else if (typeof userInfo.login === "string" && userInfo.login.trim()) {
        displayName = userInfo.login.trim();
      }
      if (typeof userInfo.avatar_url === "string" && userInfo.avatar_url.trim()) {
        avatarUrl = userInfo.avatar_url.trim();
      }
      if (userInfo.id !== undefined && userInfo.id !== null) {
        providerUserId = String(userInfo.id);
      }
      if (!email) {
        const emails = await fetchJson("https://api.github.com/user/emails", {
          headers: {
            Authorization: `Bearer ${accessToken}`,
            Accept: "application/json",
            "User-Agent": "ts-memo-api",
          },
        });
        if (Array.isArray(emails)) {
          const primary = emails.find(
            (entry) => entry && entry.primary === true && entry.verified === true,
          );
          const fallback = emails.find((entry) => entry && entry.verified === true);
          const picked = primary ?? fallback;
          if (picked && typeof picked.email === "string") {
            email = picked.email.trim();
          }
        }
      }
    }

    if (!email) {
      throw new Error("OAuth email is missing");
    }

    const normalizedEmail = email.trim();
    const upserted = await pool.query(
      `INSERT INTO users (email, password_hash, display_name, avatar_url, provider, provider_user_id)
       VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT (email) DO UPDATE SET
         email = EXCLUDED.email,
         display_name = EXCLUDED.display_name,
         avatar_url = EXCLUDED.avatar_url,
         provider = EXCLUDED.provider,
         provider_user_id = EXCLUDED.provider_user_id
       RETURNING id`,
      [normalizedEmail, null, displayName, avatarUrl, provider, providerUserId],
    );
    const userId = upserted.rows[0].id;

    const jwtSecret = process.env.JWT_SECRET;
    if (!jwtSecret) {
      return res.status(500).json({ error: "JWT_SECRET is not set" });
    }
    const token = jwt.sign({ user_id: userId }, jwtSecret);

    const redirectUrl = buildFrontendRedirect(token);
    if (!redirectUrl) {
      return res.status(500).json({ error: "FRONTEND_URL is not set" });
    }
    return res.redirect(redirectUrl);
  } catch (error) {
    console.error("oauth callback failed", error);
    return res.status(500).json({ error: "internal server error" });
  }
});

app.use("/api/v1/children", authMiddleware);
app.use("/api/v1/tasks", authMiddleware);

const isValidDate = (value: string): boolean => {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) {
    return false;
  }
  const parsed = new Date(`${value}T00:00:00Z`);
  if (Number.isNaN(parsed.getTime())) {
    return false;
  }
  return parsed.toISOString().slice(0, 10) === value;
};

const weekdayInfo = (value: string): { label: string; mask: number } => {
  const date = new Date(`${value}T00:00:00Z`);
  const day = date.getUTCDay(); // 0=Sun..6=Sat
  switch (day) {
    case 1:
      return { label: "Mon", mask: 2 };
    case 2:
      return { label: "Tue", mask: 4 };
    case 3:
      return { label: "Wed", mask: 8 };
    case 4:
      return { label: "Thu", mask: 16 };
    case 5:
      return { label: "Fri", mask: 32 };
    case 6:
      return { label: "Sat", mask: 64 };
    default:
      return { label: "Sun", mask: 1 };
  }
};

const weekdayMaskSunStart = (value: string): number => {
  const date = new Date(`${value}T00:00:00Z`);
  const day = date.getUTCDay(); // 0=Sun..6=Sat
  switch (day) {
    case 1:
      return 2;
    case 2:
      return 4;
    case 3:
      return 8;
    case 4:
      return 16;
    case 5:
      return 32;
    case 6:
      return 64;
    default:
      return 1;
  }
};

const formatUtcDate = (date: Date): string => {
  return date.toISOString().slice(0, 10);
};

app.get("/api/v1/children", async (req, res) => {
  const { userId } = req as AuthenticatedRequest;

  try {
    const result = await pool.query(
      "SELECT id, name, grade FROM children WHERE user_id = $1 AND is_active = true ORDER BY created_at ASC",
      [userId],
    );
    return res.json(result.rows);
  } catch (error) {
    console.error("list children failed", error);
    return res.status(500).json({ error: "internal server error" });
  }
});

app.post("/api/v1/children", async (req, res) => {
  const { userId } = req as AuthenticatedRequest;
  const { name, grade } = req.body ?? {};

  if (typeof name !== "string" || !name.trim()) {
    return res.status(400).json({ error: "invalid_request" });
  }
  if (grade !== undefined && typeof grade !== "string") {
    return res.status(400).json({ error: "invalid_request" });
  }

  try {
    const result = await pool.query(
      "INSERT INTO children (user_id, name, grade) VALUES ($1, $2, $3) RETURNING id, name, grade, is_active",
      [userId, name.trim(), grade ?? null],
    );
    return res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error("create child failed", error);
    return res.status(500).json({ error: "internal server error" });
  }
});

app.patch("/api/v1/children/:childId", async (req, res) => {
  const { userId } = req as AuthenticatedRequest;
  const { childId } = req.params;
  const { name, grade, is_active } = req.body ?? {};

  if (!isUuid(childId)) {
    return res.status(400).json({ error: "invalid_request" });
  }

  const fields: string[] = [];
  const values: unknown[] = [];
  let index = 1;

  if (name !== undefined) {
    if (typeof name !== "string" || !name.trim()) {
      return res.status(400).json({ error: "invalid_request" });
    }
    fields.push(`name = $${index++}`);
    values.push(name.trim());
  }

  if (grade !== undefined) {
    if (typeof grade !== "string") {
      return res.status(400).json({ error: "invalid_request" });
    }
    fields.push(`grade = $${index++}`);
    values.push(grade);
  }

  if (is_active !== undefined) {
    if (typeof is_active !== "boolean") {
      return res.status(400).json({ error: "invalid_request" });
    }
    fields.push(`is_active = $${index++}`);
    values.push(is_active);
  }

  if (fields.length === 0) {
    return res.status(400).json({ error: "invalid_request" });
  }

  fields.push("updated_at = now()");
  values.push(childId, userId);

  try {
    const result = await pool.query(
      `UPDATE children SET ${fields.join(", ")} WHERE id = $${index++} AND user_id = $${index} RETURNING id, name, grade, is_active`,
      values,
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: "not_found" });
    }

    return res.json(result.rows[0]);
  } catch (error) {
    console.error("update child failed", error);
    return res.status(500).json({ error: "internal server error" });
  }
});

app.put("/api/v1/children/:id", async (req, res) => {
  const { userId } = req as AuthenticatedRequest;
  const { id } = req.params;
  const { name, grade } = req.body ?? {};

  if (!isUuid(id)) {
    return res.status(400).json({ error: "invalid_request" });
  }
  if (typeof name !== "string" || !name.trim()) {
    return res.status(400).json({ error: "invalid_request" });
  }
  if (
    grade !== undefined &&
    grade !== null &&
    typeof grade !== "string"
  ) {
    return res.status(400).json({ error: "invalid_request" });
  }

  const normalizedGrade =
    grade === undefined || grade === null || grade.trim() === ""
      ? null
      : grade.trim();

  try {
    const result = await pool.query(
      `UPDATE children
       SET name = $1, grade = $2, updated_at = now()
       WHERE id = $3 AND user_id = $4
       RETURNING id, name, grade, is_active`,
      [name.trim(), normalizedGrade, id, userId],
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: "not_found" });
    }

    return res.json(result.rows[0]);
  } catch (error) {
    console.error("update child (put) failed", error);
    return res.status(500).json({ error: "internal server error" });
  }
});

app.delete("/api/v1/children/:childId", async (req, res) => {
  const { userId } = req as AuthenticatedRequest;
  const { childId } = req.params;

  if (!isUuid(childId)) {
    return res.status(400).json({ error: "invalid_request" });
  }

  try {
    const result = await pool.query(
      "UPDATE children SET is_active = false, updated_at = now() WHERE id = $1 AND user_id = $2",
      [childId, userId],
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: "not_found" });
    }

    return res.status(204).send();
  } catch (error) {
    console.error("delete child failed", error);
    return res.status(500).json({ error: "internal server error" });
  }
});

app.get("/api/v1/children/:childId/tasks", async (req, res) => {
  const { userId } = req as AuthenticatedRequest;
  const { childId } = req.params;
  const archivedParam = req.query.archived;

  if (!isUuid(childId)) {
    return res.status(400).json({ error: "invalid_request" });
  }

  let archived = false;
  if (archivedParam !== undefined) {
    if (archivedParam === "true") {
      archived = true;
    } else if (archivedParam === "false") {
      archived = false;
    } else {
      return res.status(400).json({ error: "invalid_request" });
    }
  }

  try {
    const childResult = await pool.query(
      "SELECT 1 FROM children WHERE id = $1 AND user_id = $2",
      [childId, userId],
    );
    if (childResult.rowCount === 0) {
      return res.status(404).json({ error: "not_found" });
    }

    const result = await pool.query(
      `SELECT id,
              name,
              description,
              subject,
              default_minutes,
              days_mask,
              is_archived,
              TO_CHAR(start_date, 'YYYY-MM-DD') AS start_date,
              TO_CHAR(end_date, 'YYYY-MM-DD') AS end_date
       FROM tasks
       WHERE child_id = $1 AND user_id = $2 AND is_archived = $3
       ORDER BY sort_order ASC`,
      [childId, userId, archived],
    );
    return res.json(result.rows);
  } catch (error) {
    console.error("list tasks failed", error);
    return res.status(500).json({ error: "internal server error" });
  }
});

app.get("/api/v1/children/:childId/daily-view", async (req, res) => {
  const { userId } = req as AuthenticatedRequest;
  const { childId } = req.params;
  const dateParam = req.query.date;

  if (!isUuid(childId)) {
    return res.status(400).json({ error: "invalid_request" });
  }
  if (typeof dateParam !== "string" || !isValidDate(dateParam)) {
    return res.status(400).json({ error: "invalid_request" });
  }

  const { label: weekday, mask: todayMask } = weekdayInfo(dateParam);

  try {
    const childResult = await pool.query(
      "SELECT 1 FROM children WHERE id = $1 AND user_id = $2",
      [childId, userId],
    );
    if (childResult.rowCount === 0) {
      return res.status(404).json({ error: "not_found" });
    }

    const tasksResult = await pool.query(
      `SELECT id, name, subject, default_minutes, days_mask
       FROM tasks
       WHERE child_id = $1
         AND user_id = $2
         AND is_archived = false
         AND (days_mask & $3) != 0
         AND (start_date IS NULL OR start_date <= $4::date)
         AND (end_date IS NULL OR end_date >= $4::date)
       ORDER BY sort_order ASC`,
      [childId, userId, todayMask, dateParam],
    );

    const logsResult = await pool.query(
      "SELECT task_id, minutes FROM study_logs WHERE child_id = $1 AND user_id = $2 AND date = $3",
      [childId, userId, dateParam],
    );

    const logByTaskId = new Map<string, number>();
    for (const row of logsResult.rows) {
      logByTaskId.set(row.task_id, row.minutes);
    }

    const tasks = tasksResult.rows.map((task) => {
      const loggedMinutes = logByTaskId.get(task.id);
      if (loggedMinutes !== undefined) {
        return {
          task_id: task.id,
          name: task.name,
          subject: task.subject,
          default_minutes: task.default_minutes,
          days_mask: task.days_mask,
          is_done: true,
          minutes: loggedMinutes,
        };
      }
      return {
        task_id: task.id,
        name: task.name,
        subject: task.subject,
        default_minutes: task.default_minutes,
        days_mask: task.days_mask,
        is_done: false,
        minutes: task.default_minutes,
      };
    });

    return res.json({ date: dateParam, weekday, tasks });
  } catch (error) {
    console.error("get daily view failed", error);
    return res.status(500).json({ error: "internal server error" });
  }
});

app.get("/api/v1/children/:childId/calendar-summary", async (req, res) => {
  const { userId } = req as AuthenticatedRequest;
  const { childId } = req.params;
  const fromParam = req.query.from;
  const toParam = req.query.to;

  if (!isUuid(childId)) {
    return res.status(400).json({ error: "invalid_request" });
  }
  if (typeof fromParam !== "string" || !isValidDate(fromParam)) {
    return res.status(400).json({ error: "invalid_request" });
  }
  if (typeof toParam !== "string" || !isValidDate(toParam)) {
    return res.status(400).json({ error: "invalid_request" });
  }

  const fromDate = new Date(`${fromParam}T00:00:00Z`);
  const toDate = new Date(`${toParam}T00:00:00Z`);
  if (fromDate.getTime() > toDate.getTime()) {
    return res.status(400).json({ error: "invalid_request" });
  }

  const dayCount =
    Math.floor((toDate.getTime() - fromDate.getTime()) / 86400000) + 1;
  if (dayCount > 62) {
    return res.status(400).json({ error: "invalid_request" });
  }

  try {
    const childResult = await pool.query(
      "SELECT 1 FROM children WHERE id = $1 AND user_id = $2",
      [childId, userId],
    );
    if (childResult.rowCount === 0) {
      return res.status(404).json({ error: "not_found" });
    }

    const tasksResult = await pool.query(
      `SELECT id, days_mask, start_date, end_date
       FROM tasks
       WHERE child_id = $1 AND user_id = $2 AND is_archived = false`,
      [childId, userId],
    );

    const logsResult = await pool.query(
      `SELECT task_id, TO_CHAR(date, 'YYYY-MM-DD') AS date_key
       FROM study_logs
       WHERE child_id = $1 AND user_id = $2 AND date BETWEEN $3 AND $4`,
      [childId, userId, fromParam, toParam],
    );

    const logsByDate = new Map<string, Set<string>>();
    for (const row of logsResult.rows) {
      const dateKey = String(row.date_key);
      const set = logsByDate.get(dateKey) ?? new Set<string>();
      set.add(row.task_id);
      logsByDate.set(dateKey, set);
    }

    const todayUtc = formatUtcDate(new Date());
    const days: Array<{ date: string; status: string; total: number; done: number }> = [];

    for (let i = 0; i < dayCount; i += 1) {
      const current = new Date(fromDate);
      current.setUTCDate(fromDate.getUTCDate() + i);
      const dateKey = current.toISOString().slice(0, 10);
      const todayMask = weekdayMaskSunStart(dateKey);

      const targetTasks = tasksResult.rows.filter((task) => {
        if ((task.days_mask & todayMask) === 0) {
          return false;
        }
        if (task.start_date && String(task.start_date).slice(0, 10) > dateKey) {
          return false;
        }
        if (task.end_date && String(task.end_date).slice(0, 10) < dateKey) {
          return false;
        }
        return true;
      });
      const total = targetTasks.length;

      let done = 0;
      const doneSet = logsByDate.get(dateKey);
      if (doneSet && total > 0) {
        for (const task of targetTasks) {
          if (doneSet.has(task.id)) {
            done += 1;
          }
        }
      }

      let status = "red";
      if (dateKey > todayUtc) {
        status = "white";
      } else if (total === 0) {
        status = "white";
      } else if (done === total) {
        status = "green";
      } else if (done > 0) {
        status = "yellow";
      }

      days.push({ date: dateKey, status, total, done });
    }

    return res.json({ from: fromParam, to: toParam, days });
  } catch (error) {
    console.error("get calendar summary failed", error);
    return res.status(500).json({ error: "internal server error" });
  }
});

app.get("/api/v1/children/:childId/summary", async (req, res) => {
  const { userId } = req as AuthenticatedRequest;
  const { childId } = req.params;
  const fromParam = req.query.from;
  const toParam = req.query.to;

  if (!isUuid(childId)) {
    return res.status(400).json({ error: "invalid_request" });
  }
  if (typeof fromParam !== "string" || !isValidDate(fromParam)) {
    return res.status(400).json({ error: "invalid_request" });
  }
  if (typeof toParam !== "string" || !isValidDate(toParam)) {
    return res.status(400).json({ error: "invalid_request" });
  }

  const fromDate = new Date(`${fromParam}T00:00:00Z`);
  const toDate = new Date(`${toParam}T00:00:00Z`);
  if (fromDate.getTime() > toDate.getTime()) {
    return res.status(400).json({ error: "invalid_request" });
  }

  const dayCount =
    Math.floor((toDate.getTime() - fromDate.getTime()) / 86400000) + 1;
  if (dayCount > 366) {
    return res.status(400).json({ error: "invalid_request" });
  }

  try {
    const childResult = await pool.query(
      "SELECT 1 FROM children WHERE id = $1 AND user_id = $2",
      [childId, userId],
    );
    if (childResult.rowCount === 0) {
      return res.status(404).json({ error: "not_found" });
    }

    const totalResult = await pool.query(
      `SELECT COALESCE(SUM(minutes), 0) AS total_minutes
       FROM study_logs
       WHERE child_id = $1 AND user_id = $2 AND date BETWEEN $3 AND $4`,
      [childId, userId, fromParam, toParam],
    );

    const byDayResult = await pool.query(
      `SELECT TO_CHAR(date, 'YYYY-MM-DD') AS date_key, SUM(minutes) AS minutes
       FROM study_logs
       WHERE child_id = $1 AND user_id = $2 AND date BETWEEN $3 AND $4
       GROUP BY date
       ORDER BY date ASC`,
      [childId, userId, fromParam, toParam],
    );

    const bySubjectResult = await pool.query(
      `SELECT t.subject AS subject, SUM(s.minutes) AS minutes
       FROM study_logs s
       JOIN tasks t ON t.id = s.task_id
       WHERE s.child_id = $1 AND s.user_id = $2 AND s.date BETWEEN $3 AND $4
       GROUP BY t.subject
       ORDER BY minutes DESC`,
      [childId, userId, fromParam, toParam],
    );

    const byTaskResult = await pool.query(
      `SELECT s.task_id AS task_id, t.name AS name, t.subject AS subject, SUM(s.minutes) AS minutes
       FROM study_logs s
       JOIN tasks t ON t.id = s.task_id
       WHERE s.child_id = $1 AND s.user_id = $2 AND s.date BETWEEN $3 AND $4
       GROUP BY s.task_id, t.name, t.subject
       ORDER BY minutes DESC`,
      [childId, userId, fromParam, toParam],
    );

    const totalMinutes = Number(totalResult.rows[0]?.total_minutes ?? 0);

    const byDay = byDayResult.rows.map((row) => ({
      date: String(row.date_key),
      minutes: Number(row.minutes),
    }));

    const bySubject = bySubjectResult.rows.map((row) => ({
      subject: row.subject,
      minutes: Number(row.minutes),
    }));

    const byTask = byTaskResult.rows.map((row) => ({
      task_id: row.task_id,
      name: row.name,
      subject: row.subject,
      minutes: Number(row.minutes),
    }));

    return res.json({
      from: fromParam,
      to: toParam,
      total_minutes: totalMinutes,
      by_day: byDay,
      by_subject: bySubject,
      by_task: byTask,
    });
  } catch (error) {
    console.error("get summary failed", error);
    return res.status(500).json({ error: "internal server error" });
  }
});

app.get("/api/v1/children/:childId/daily", async (req, res) => {
  const { userId } = req as AuthenticatedRequest;
  const { childId } = req.params;
  const dateParam = req.query.date;

  if (!isUuid(childId)) {
    return res.status(400).json({ error: "invalid_request" });
  }
  if (typeof dateParam !== "string" || !isValidDate(dateParam)) {
    return res.status(400).json({ error: "invalid_request" });
  }

  try {
    const childResult = await pool.query(
      "SELECT 1 FROM children WHERE id = $1 AND user_id = $2",
      [childId, userId],
    );
    if (childResult.rowCount === 0) {
      return res.status(404).json({ error: "not_found" });
    }

    const result = await pool.query(
      `SELECT task_id, minutes
       FROM study_logs
       WHERE child_id = $1 AND user_id = $2 AND date = $3
       ORDER BY created_at ASC`,
      [childId, userId, dateParam],
    );

    return res.json({ date: dateParam, items: result.rows });
  } catch (error) {
    console.error("get daily failed", error);
    return res.status(500).json({ error: "internal server error" });
  }
});

app.put("/api/v1/children/:childId/daily", async (req, res) => {
  const { userId } = req as AuthenticatedRequest;
  const { childId } = req.params;
  const dateParam = req.query.date;
  const { items } = req.body ?? {};

  if (!isUuid(childId)) {
    return res.status(400).json({ error: "invalid_request" });
  }
  if (typeof dateParam !== "string" || !isValidDate(dateParam)) {
    return res.status(400).json({ error: "invalid_request" });
  }
  if (!Array.isArray(items)) {
    return res.status(400).json({ error: "invalid_request" });
  }

  const taskIdSet = new Set<string>();
  for (const item of items) {
    if (typeof item !== "object" || item === null) {
      return res.status(400).json({ error: "invalid_request" });
    }
    if (typeof item.task_id !== "string" || !isUuid(item.task_id)) {
      return res.status(400).json({ error: "invalid_request" });
    }
    if (taskIdSet.has(item.task_id)) {
      return res
        .status(400)
        .json({ error: "Duplicate task_id is not allowed" });
    }
    taskIdSet.add(item.task_id);
    if (typeof item.minutes !== "number" || !Number.isInteger(item.minutes)) {
      return res.status(400).json({ error: "invalid_request" });
    }
    if (item.minutes < 1) {
      return res.status(400).json({ error: "invalid_request" });
    }
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    const childResult = await client.query(
      "SELECT 1 FROM children WHERE id = $1 AND user_id = $2",
      [childId, userId],
    );
    if (childResult.rowCount === 0) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "not_found" });
    }

    if (items.length > 0) {
      const taskIds = Array.from(taskIdSet);
      const taskResult = await client.query(
        "SELECT id FROM tasks WHERE user_id = $1 AND child_id = $2 AND id = ANY($3::uuid[])",
        [userId, childId, taskIds],
      );
      if (taskResult.rowCount !== taskIds.length) {
        await client.query("ROLLBACK");
        return res.status(404).json({ error: "not_found" });
      }
    }

    await client.query(
      "DELETE FROM study_logs WHERE child_id = $1 AND user_id = $2 AND date = $3",
      [childId, userId, dateParam],
    );

    if (items.length > 0) {
      const values: unknown[] = [];
      const placeholders = items
        .map((item, idx) => {
          const baseIndex = idx * 5;
          values.push(userId, childId, item.task_id, dateParam, item.minutes);
          return `($${baseIndex + 1}, $${baseIndex + 2}, $${baseIndex + 3}, $${baseIndex + 4}, $${baseIndex + 5})`;
        })
        .join(", ");

      await client.query(
        `INSERT INTO study_logs (user_id, child_id, task_id, date, minutes)
         VALUES ${placeholders}`,
        values,
      );
    }

    await client.query("COMMIT");
    return res.json({ date: dateParam, saved_count: items.length });
  } catch (error) {
    await client.query("ROLLBACK");
    console.error("put daily failed", error);
    return res.status(500).json({ error: "internal server error" });
  } finally {
    client.release();
  }
});

app.post("/api/v1/children/:childId/tasks", async (req, res) => {
  const { userId } = req as AuthenticatedRequest;
  const { childId } = req.params;
  const {
    name,
    description,
    subject,
    default_minutes,
    days_mask,
    start_date,
    end_date,
  } = req.body ?? {};

  if (!isUuid(childId)) {
    return res.status(400).json({ error: "invalid_request" });
  }

  if (typeof name !== "string" || !name.trim()) {
    return res.status(400).json({ error: "invalid_request" });
  }
  if (typeof subject !== "string" || !subject.trim()) {
    return res.status(400).json({ error: "invalid_request" });
  }
  if (description !== undefined && description !== null && typeof description !== "string") {
    return res.status(400).json({ error: "invalid_request" });
  }
  if (default_minutes !== undefined && typeof default_minutes !== "number") {
    return res.status(400).json({ error: "invalid_request" });
  }
  const minutes = default_minutes ?? 15;
  if (!Number.isInteger(minutes) || minutes < 1) {
    return res.status(400).json({ error: "invalid_request" });
  }
  if (typeof days_mask !== "number" || !Number.isInteger(days_mask)) {
    return res.status(400).json({ error: "invalid_request" });
  }
  if (days_mask < 1 || days_mask > 127) {
    return res.status(400).json({ error: "invalid_request" });
  }

  let startDate: string | null | undefined = undefined;
  let endDate: string | null | undefined = undefined;

  if (start_date !== undefined) {
    if (start_date === null) {
      startDate = null;
    } else if (typeof start_date === "string" && isValidDate(start_date)) {
      startDate = start_date;
    } else {
      return res.status(400).json({ error: "invalid_request" });
    }
  }

  if (end_date !== undefined) {
    if (end_date === null) {
      endDate = null;
    } else if (typeof end_date === "string" && isValidDate(end_date)) {
      endDate = end_date;
    } else {
      return res.status(400).json({ error: "invalid_request" });
    }
  }

  if (
    startDate !== undefined &&
    endDate !== undefined &&
    startDate !== null &&
    endDate !== null &&
    startDate > endDate
  ) {
    return res.status(400).json({ error: "invalid_request" });
  }

  try {
    const childResult = await pool.query(
      "SELECT 1 FROM children WHERE id = $1 AND user_id = $2",
      [childId, userId],
    );
    if (childResult.rowCount === 0) {
      return res.status(404).json({ error: "not_found" });
    }

    const result = await pool.query(
      `INSERT INTO tasks (user_id, child_id, name, description, subject, default_minutes, days_mask, start_date, end_date)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
       RETURNING id,
                 name,
                 description,
                 subject,
                 default_minutes,
                 days_mask,
                 is_archived,
                 TO_CHAR(start_date, 'YYYY-MM-DD') AS start_date,
                 TO_CHAR(end_date, 'YYYY-MM-DD') AS end_date`,
      [
        userId,
        childId,
        name.trim(),
        description ?? null,
        subject.trim(),
        minutes,
        days_mask,
        startDate ?? null,
        endDate ?? null,
      ],
    );
    return res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error("create task failed", error);
    return res.status(500).json({ error: "internal server error" });
  }
});

app.put("/api/v1/children/:childId/tasks/reorder", async (req, res) => {
  const { userId } = req as AuthenticatedRequest;
  const { childId } = req.params;
  const { orders, items } = req.body ?? {};
  const payloadOrders = Array.isArray(orders) ? orders : items;

  if (!isUuid(childId)) {
    return res.status(400).json({ error: "invalid_request" });
  }
  if (!Array.isArray(payloadOrders) || payloadOrders.length === 0) {
    return res.status(400).json({ error: "invalid_request" });
  }

  const taskIdSet = new Set<string>();
  for (const item of payloadOrders) {
    if (typeof item !== "object" || item === null) {
      return res.status(400).json({ error: "invalid_request" });
    }
    if (typeof item.task_id !== "string" || !isUuid(item.task_id)) {
      return res.status(400).json({ error: "invalid_request" });
    }
    if (taskIdSet.has(item.task_id)) {
      return res.status(400).json({ error: "invalid_request" });
    }
    if (typeof item.sort_order !== "number" || !Number.isInteger(item.sort_order)) {
      return res.status(400).json({ error: "invalid_request" });
    }
    taskIdSet.add(item.task_id);
  }

  const taskIds = Array.from(taskIdSet);
  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    const childResult = await client.query(
      "SELECT 1 FROM children WHERE id = $1 AND user_id = $2",
      [childId, userId],
    );
    if (childResult.rowCount === 0) {
      await client.query("ROLLBACK");
      return res.status(403).json({ error: "forbidden" });
    }

    const taskResult = await client.query(
      "SELECT id FROM tasks WHERE user_id = $1 AND child_id = $2 AND id = ANY($3::uuid[])",
      [userId, childId, taskIds],
    );
    if (taskResult.rowCount !== taskIds.length) {
      await client.query("ROLLBACK");
      return res.status(403).json({ error: "forbidden" });
    }

    const values: unknown[] = [];
    const placeholders = payloadOrders
      .map((item, idx) => {
        const baseIndex = idx * 2;
        values.push(item.task_id, item.sort_order);
        return `($${baseIndex + 1}::uuid, $${baseIndex + 2}::int)`;
      })
      .join(", ");
    values.push(childId, userId);

    const updateResult = await client.query(
      `UPDATE tasks
       SET sort_order = updates.sort_order,
           updated_at = now()
       FROM (VALUES ${placeholders}) AS updates(id, sort_order)
       WHERE tasks.id = updates.id
         AND tasks.child_id = $${values.length - 1}
         AND tasks.user_id = $${values.length}
       RETURNING tasks.id`,
      values,
    );

    await client.query("COMMIT");
    return res.json({ updated: updateResult.rowCount });
  } catch (error) {
    await client.query("ROLLBACK");
    console.error("reorder tasks failed", error);
    return res.status(500).json({ error: "internal server error" });
  } finally {
    client.release();
  }
});

app.put("/api/v1/children/:childId/tasks/:taskId", async (req, res) => {
  const { userId } = req as AuthenticatedRequest;
  const { childId, taskId } = req.params;
  const {
    name,
    description,
    subject,
    default_minutes,
    days_mask,
    is_archived,
    start_date,
    end_date,
  } = req.body ?? {};

  if (!isUuid(childId) || !isUuid(taskId)) {
    return res.status(400).json({ error: "invalid_request" });
  }
  if (typeof name !== "string" || !name.trim()) {
    return res.status(400).json({ error: "invalid_request" });
  }
  if (typeof subject !== "string" || !subject.trim()) {
    return res.status(400).json({ error: "invalid_request" });
  }
  if (description !== undefined && description !== null && typeof description !== "string") {
    return res.status(400).json({ error: "invalid_request" });
  }
  if (typeof default_minutes !== "number" || !Number.isInteger(default_minutes)) {
    return res.status(400).json({ error: "invalid_request" });
  }
  if (default_minutes < 1) {
    return res.status(400).json({ error: "invalid_request" });
  }
  if (typeof days_mask !== "number" || !Number.isInteger(days_mask)) {
    return res.status(400).json({ error: "invalid_request" });
  }
  if (days_mask < 1 || days_mask > 127) {
    return res.status(400).json({ error: "invalid_request" });
  }
  if (typeof is_archived !== "boolean") {
    return res.status(400).json({ error: "invalid_request" });
  }

  let startDate: string | null = null;
  let endDate: string | null = null;

  if (start_date !== undefined) {
    if (start_date === null) {
      startDate = null;
    } else if (typeof start_date === "string" && isValidDate(start_date)) {
      startDate = start_date;
    } else {
      return res.status(400).json({ error: "invalid_request" });
    }
  }

  if (end_date !== undefined) {
    if (end_date === null) {
      endDate = null;
    } else if (typeof end_date === "string" && isValidDate(end_date)) {
      endDate = end_date;
    } else {
      return res.status(400).json({ error: "invalid_request" });
    }
  }

  if (startDate === undefined || endDate === undefined) {
    try {
      const existing = await pool.query(
        "SELECT start_date, end_date FROM tasks WHERE id = $1 AND child_id = $2 AND user_id = $3",
        [taskId, childId, userId],
      );
      if (existing.rowCount === 0) {
        return res.status(404).json({ error: "not_found" });
      }
      const currentStart = existing.rows[0].start_date
        ? String(existing.rows[0].start_date).slice(0, 10)
        : null;
      const currentEnd = existing.rows[0].end_date
        ? String(existing.rows[0].end_date).slice(0, 10)
        : null;
      if (startDate === undefined) {
        startDate = currentStart;
      }
      if (endDate === undefined) {
        endDate = currentEnd;
      }
    } catch (error) {
      console.error("put task date validation failed", error);
      return res.status(500).json({ error: "internal server error" });
    }
  }

  if (startDate !== null && endDate !== null && startDate > endDate) {
    return res.status(400).json({ error: "invalid_request" });
  }

  try {
    const result = await pool.query(
      `UPDATE tasks
       SET name = $1,
           description = $2,
           subject = $3,
           default_minutes = $4,
           days_mask = $5,
           is_archived = $6,
           start_date = $7,
           end_date = $8,
           updated_at = now()
       WHERE id = $9 AND child_id = $10 AND user_id = $11
       RETURNING id,
                 name,
                 description,
                 subject,
                 default_minutes,
                 days_mask,
                 is_archived,
                 TO_CHAR(start_date, 'YYYY-MM-DD') AS start_date,
                 TO_CHAR(end_date, 'YYYY-MM-DD') AS end_date`,
      [
        name.trim(),
        description ?? null,
        subject.trim(),
        default_minutes,
        days_mask,
        is_archived,
        startDate,
        endDate,
        taskId,
        childId,
        userId,
      ],
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: "not_found" });
    }

    return res.json(result.rows[0]);
  } catch (error) {
    console.error("update task (put) failed", error);
    return res.status(500).json({ error: "internal server error" });
  }
});

app.patch("/api/v1/tasks/:taskId", async (req, res) => {
  const { userId } = req as AuthenticatedRequest;
  const { taskId } = req.params;
  const {
    name,
    description,
    subject,
    default_minutes,
    days_mask,
    is_archived,
    start_date,
    end_date,
  } = req.body ?? {};

  if (!isUuid(taskId)) {
    return res.status(400).json({ error: "invalid_request" });
  }

  const fields: string[] = [];
  const values: unknown[] = [];
  let index = 1;

  if (name !== undefined) {
    if (typeof name !== "string" || !name.trim()) {
      return res.status(400).json({ error: "invalid_request" });
    }
    fields.push(`name = $${index++}`);
    values.push(name.trim());
  }

  if (description !== undefined) {
    if (description !== null && typeof description !== "string") {
      return res.status(400).json({ error: "invalid_request" });
    }
    fields.push(`description = $${index++}`);
    values.push(description);
  }

  if (subject !== undefined) {
    if (typeof subject !== "string" || !subject.trim()) {
      return res.status(400).json({ error: "invalid_request" });
    }
    fields.push(`subject = $${index++}`);
    values.push(subject.trim());
  }

  if (default_minutes !== undefined) {
    if (typeof default_minutes !== "number" || !Number.isInteger(default_minutes)) {
      return res.status(400).json({ error: "invalid_request" });
    }
    if (default_minutes < 1) {
      return res.status(400).json({ error: "invalid_request" });
    }
    fields.push(`default_minutes = $${index++}`);
    values.push(default_minutes);
  }

  if (days_mask !== undefined) {
    if (typeof days_mask !== "number" || !Number.isInteger(days_mask)) {
      return res.status(400).json({ error: "invalid_request" });
    }
    if (days_mask < 1 || days_mask > 127) {
      return res.status(400).json({ error: "invalid_request" });
    }
    fields.push(`days_mask = $${index++}`);
    values.push(days_mask);
  }

  if (is_archived !== undefined) {
    if (typeof is_archived !== "boolean") {
      return res.status(400).json({ error: "invalid_request" });
    }
    fields.push(`is_archived = $${index++}`);
    values.push(is_archived);
  }

  let startDate: string | null | undefined;
  let endDate: string | null | undefined;

  if (start_date !== undefined) {
    if (start_date === null) {
      startDate = null;
    } else if (typeof start_date === "string" && isValidDate(start_date)) {
      startDate = start_date;
    } else {
      return res.status(400).json({ error: "invalid_request" });
    }
    fields.push(`start_date = $${index++}`);
    values.push(startDate);
  }

  if (end_date !== undefined) {
    if (end_date === null) {
      endDate = null;
    } else if (typeof end_date === "string" && isValidDate(end_date)) {
      endDate = end_date;
    } else {
      return res.status(400).json({ error: "invalid_request" });
    }
    fields.push(`end_date = $${index++}`);
    values.push(endDate);
  }

  if (startDate !== undefined || endDate !== undefined) {
    try {
      const existing = await pool.query(
        "SELECT start_date, end_date FROM tasks WHERE id = $1 AND user_id = $2",
        [taskId, userId],
      );
      if (existing.rowCount === 0) {
        return res.status(404).json({ error: "not_found" });
      }
      const currentStart = existing.rows[0].start_date
        ? String(existing.rows[0].start_date).slice(0, 10)
        : null;
      const currentEnd = existing.rows[0].end_date
        ? String(existing.rows[0].end_date).slice(0, 10)
        : null;
      const nextStart = startDate !== undefined ? startDate : currentStart;
      const nextEnd = endDate !== undefined ? endDate : currentEnd;

      if (nextStart !== null && nextEnd !== null && nextStart > nextEnd) {
        return res.status(400).json({ error: "invalid_request" });
      }
    } catch (error) {
      console.error("patch task date validation failed", error);
      return res.status(500).json({ error: "internal server error" });
    }
  }

  if (fields.length === 0) {
    return res.status(400).json({ error: "invalid_request" });
  }

  fields.push("updated_at = now()");
  values.push(taskId, userId);

  try {
    const result = await pool.query(
      `UPDATE tasks SET ${fields.join(", ")}
       WHERE id = $${index++} AND user_id = $${index}
       RETURNING id,
                 name,
                 description,
                 subject,
                 default_minutes,
                 days_mask,
                 is_archived,
                 TO_CHAR(start_date, 'YYYY-MM-DD') AS start_date,
                 TO_CHAR(end_date, 'YYYY-MM-DD') AS end_date`,
      values,
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: "not_found" });
    }

    return res.json(result.rows[0]);
  } catch (error) {
    console.error("update task failed", error);
    return res.status(500).json({ error: "internal server error" });
  }
});

const port = Number(process.env.PORT) || 3000;
app.listen(port, () => {
  console.log(`API server running: http://localhost:${port}`);
});
