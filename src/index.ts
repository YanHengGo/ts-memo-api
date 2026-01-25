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

const weekdayMaskMonStart = (value: string): number => {
  const date = new Date(`${value}T00:00:00Z`);
  const day = date.getUTCDay(); // 0=Sun..6=Sat
  switch (day) {
    case 1:
      return 1;
    case 2:
      return 2;
    case 3:
      return 4;
    case 4:
      return 8;
    case 5:
      return 16;
    case 6:
      return 32;
    default:
      return 64;
  }
};

const formatLocalDate = (date: Date): string => {
  const year = date.getFullYear();
  const month = `${date.getMonth() + 1}`.padStart(2, "0");
  const day = `${date.getDate()}`.padStart(2, "0");
  return `${year}-${month}-${day}`;
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
       ORDER BY subject ASC, name ASC`,
      [childId, userId, todayMask],
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
      `SELECT id, days_mask
       FROM tasks
       WHERE child_id = $1 AND user_id = $2 AND is_archived = false`,
      [childId, userId],
    );

    const logsResult = await pool.query(
      `SELECT task_id, date
       FROM study_logs
       WHERE child_id = $1 AND user_id = $2 AND date BETWEEN $3 AND $4`,
      [childId, userId, fromParam, toParam],
    );

    const logsByDate = new Map<string, Set<string>>();
    for (const row of logsResult.rows) {
      const dateKey = row.date instanceof Date ? row.date.toISOString().slice(0, 10) : String(row.date);
      const set = logsByDate.get(dateKey) ?? new Set<string>();
      set.add(row.task_id);
      logsByDate.set(dateKey, set);
    }

    const todayLocal = formatLocalDate(new Date());
    const days: Array<{ date: string; status: string; total: number; done: number }> = [];

    for (let i = 0; i < dayCount; i += 1) {
      const current = new Date(fromDate);
      current.setUTCDate(fromDate.getUTCDate() + i);
      const dateKey = current.toISOString().slice(0, 10);
      const todayMask = weekdayMaskMonStart(dateKey);

      const targetTasks = tasksResult.rows.filter(
        (task) => (task.days_mask & todayMask) !== 0,
      );
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
      if (dateKey > todayLocal) {
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
