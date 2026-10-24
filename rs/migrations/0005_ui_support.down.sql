-- 0005_ui_support.down.sql — reverse of 0005_ui_support.up.sql

DROP TRIGGER IF EXISTS trg_global_limits_updated_at ON global_limits;
DROP TABLE IF EXISTS global_limits;

DROP TABLE IF EXISTS anomaly_alerts;

DROP TRIGGER IF EXISTS trg_access_requests_updated_at ON access_requests;
DROP TABLE IF EXISTS access_requests;
