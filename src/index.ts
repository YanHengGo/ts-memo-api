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

const port = Number(process.env.PORT) || 3000;
app.listen(port, () => {
  console.log(`API server running: http://localhost:${port}`);
});
