CREATE TABLE IF NOT EXISTS study_logs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users(id),
  child_id uuid NOT NULL REFERENCES children(id),
  task_id uuid NOT NULL REFERENCES tasks(id),
  date date NOT NULL,
  minutes int NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (child_id, date, task_id),
  CHECK (minutes >= 1)
);

CREATE INDEX IF NOT EXISTS idx_study_logs_child_date ON study_logs(child_id, date);
CREATE INDEX IF NOT EXISTS idx_study_logs_user_id ON study_logs(user_id);
