import bcrypt from "bcrypt";
import express from "express";
import jwt from "jsonwebtoken";
import { pool } from "./db";

const app = express();
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
      "INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email, created_at, updated_at",
      [normalizedEmail, passwordHash],
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

    const isValid = await bcrypt.compare(password, user.password_hash);
    if (!isValid) {
      return res.status(401).json({ error: "invalid credentials" });
    }

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

app.use("/api/v1/children", authMiddleware);
app.use("/api/v1/tasks", authMiddleware);

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
      `SELECT id, name, description, subject, default_minutes, days_mask, is_archived
       FROM tasks
       WHERE child_id = $1 AND user_id = $2 AND is_archived = $3
       ORDER BY created_at ASC`,
      [childId, userId, archived],
    );
    return res.json(result.rows);
  } catch (error) {
    console.error("list tasks failed", error);
    return res.status(500).json({ error: "internal server error" });
  }
});

app.post("/api/v1/children/:childId/tasks", async (req, res) => {
  const { userId } = req as AuthenticatedRequest;
  const { childId } = req.params;
  const { name, description, subject, default_minutes, days_mask } = req.body ?? {};

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

  try {
    const childResult = await pool.query(
      "SELECT 1 FROM children WHERE id = $1 AND user_id = $2",
      [childId, userId],
    );
    if (childResult.rowCount === 0) {
      return res.status(404).json({ error: "not_found" });
    }

    const result = await pool.query(
      `INSERT INTO tasks (user_id, child_id, name, description, subject, default_minutes, days_mask)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING id, name, description, subject, default_minutes, days_mask, is_archived`,
      [
        userId,
        childId,
        name.trim(),
        description ?? null,
        subject.trim(),
        minutes,
        days_mask,
      ],
    );
    return res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error("create task failed", error);
    return res.status(500).json({ error: "internal server error" });
  }
});

app.patch("/api/v1/tasks/:taskId", async (req, res) => {
  const { userId } = req as AuthenticatedRequest;
  const { taskId } = req.params;
  const { name, description, subject, default_minutes, days_mask, is_archived } =
    req.body ?? {};

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

  if (fields.length === 0) {
    return res.status(400).json({ error: "invalid_request" });
  }

  fields.push("updated_at = now()");
  values.push(taskId, userId);

  try {
    const result = await pool.query(
      `UPDATE tasks SET ${fields.join(", ")}
       WHERE id = $${index++} AND user_id = $${index}
       RETURNING id, name, description, subject, default_minutes, days_mask, is_archived`,
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
