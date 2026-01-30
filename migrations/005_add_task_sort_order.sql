ALTER TABLE tasks
  ADD COLUMN IF NOT EXISTS sort_order integer NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_tasks_child_sort_order ON tasks(child_id, sort_order);
