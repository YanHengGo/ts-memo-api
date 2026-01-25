CREATE TABLE IF NOT EXISTS tasks (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users(id),
  child_id uuid NOT NULL REFERENCES children(id),
  name text NOT NULL,
  description text NULL,
  subject text NOT NULL,
  default_minutes int NOT NULL DEFAULT 15,
  days_mask int NOT NULL,
  is_archived boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (default_minutes >= 1),
  CHECK (days_mask BETWEEN 1 AND 127)
);

CREATE INDEX IF NOT EXISTS idx_tasks_child_archived ON tasks(child_id, is_archived);
CREATE INDEX IF NOT EXISTS idx_tasks_user_id ON tasks(user_id);
