using System.Text.Json;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Governance;
using Microsoft.Data.Sqlite;

namespace AchadinhosBot.Next.Infrastructure.Governance;

public sealed class SqliteGovernanceEventStore : IGovernanceEventStore
{
    private readonly string _dbPath;
    private readonly SemaphoreSlim _mutex = new(1, 1);

    public SqliteGovernanceEventStore()
    {
        var dataDir = Path.Combine(AppContext.BaseDirectory, "data");
        Directory.CreateDirectory(dataDir);
        _dbPath = Path.Combine(dataDir, "governance.db");
        EnsureSchema();
    }

    public async Task AppendEventAsync(GovernanceEvent item, CancellationToken cancellationToken)
    {
        const string sql = """
            INSERT INTO governance_events
            (track, event_name, severity, result, skill_name, entity_type, entity_id, correlation_id, trace_id, duration_ms, ts_utc, payload_json)
            VALUES
            ($track, $event_name, $severity, $result, $skill_name, $entity_type, $entity_id, $correlation_id, $trace_id, $duration_ms, $ts_utc, $payload_json);
            """;

        await ExecuteAsync(sql, cmd =>
        {
            cmd.Parameters.AddWithValue("$track", item.Track);
            cmd.Parameters.AddWithValue("$event_name", item.EventName);
            cmd.Parameters.AddWithValue("$severity", item.Severity);
            cmd.Parameters.AddWithValue("$result", item.Result);
            cmd.Parameters.AddWithValue("$skill_name", (object?)item.SkillName ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$entity_type", (object?)item.EntityType ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$entity_id", (object?)item.EntityId ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$correlation_id", (object?)item.CorrelationId ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$trace_id", (object?)item.TraceId ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$duration_ms", (object?)item.DurationMs ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$ts_utc", item.TimestampUtc.UtcDateTime.ToString("O"));
            cmd.Parameters.AddWithValue("$payload_json", item.PayloadJson);
        }, cancellationToken);
    }

    public async Task AppendDecisionAsync(GovernanceDecision decision, CancellationToken cancellationToken)
    {
        const string sql = """
            INSERT INTO governance_decisions
            (decision_id, decision_type, severity, summary, skill_name, entity_type, entity_id, metadata_json, ts_utc)
            VALUES
            ($decision_id, $decision_type, $severity, $summary, $skill_name, $entity_type, $entity_id, $metadata_json, $ts_utc);
            """;

        await ExecuteAsync(sql, cmd =>
        {
            cmd.Parameters.AddWithValue("$decision_id", decision.DecisionId);
            cmd.Parameters.AddWithValue("$decision_type", decision.DecisionType);
            cmd.Parameters.AddWithValue("$severity", decision.Severity);
            cmd.Parameters.AddWithValue("$summary", decision.Summary);
            cmd.Parameters.AddWithValue("$skill_name", (object?)decision.SkillName ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$entity_type", (object?)decision.EntityType ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$entity_id", (object?)decision.EntityId ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$metadata_json", decision.MetadataJson);
            cmd.Parameters.AddWithValue("$ts_utc", decision.TimestampUtc.UtcDateTime.ToString("O"));
        }, cancellationToken);
    }

    public async Task AppendActionAsync(ActionExecution action, CancellationToken cancellationToken)
    {
        const string sql = """
            INSERT INTO governance_actions
            (action_id, action_type, severity, success, requires_approval, summary, output_json, ts_utc)
            VALUES
            ($action_id, $action_type, $severity, $success, $requires_approval, $summary, $output_json, $ts_utc);
            """;

        await ExecuteAsync(sql, cmd =>
        {
            cmd.Parameters.AddWithValue("$action_id", action.ActionId);
            cmd.Parameters.AddWithValue("$action_type", action.ActionType);
            cmd.Parameters.AddWithValue("$severity", action.Severity);
            cmd.Parameters.AddWithValue("$success", action.Success ? 1 : 0);
            cmd.Parameters.AddWithValue("$requires_approval", action.RequiresApproval ? 1 : 0);
            cmd.Parameters.AddWithValue("$summary", action.Summary);
            cmd.Parameters.AddWithValue("$output_json", action.OutputJson);
            cmd.Parameters.AddWithValue("$ts_utc", action.TimestampUtc.UtcDateTime.ToString("O"));
        }, cancellationToken);
    }

    public async Task UpsertIncidentAsync(IncidentState incident, CancellationToken cancellationToken)
    {
        const string sql = """
            INSERT INTO governance_incidents
            (incident_id, incident_type, severity, status, summary, evidence_json, opened_at_utc, updated_at_utc, resolved_at_utc)
            VALUES
            ($incident_id, $incident_type, $severity, $status, $summary, $evidence_json, $opened_at_utc, $updated_at_utc, $resolved_at_utc)
            ON CONFLICT(incident_id) DO UPDATE SET
                incident_type = excluded.incident_type,
                severity = excluded.severity,
                status = excluded.status,
                summary = excluded.summary,
                evidence_json = excluded.evidence_json,
                updated_at_utc = excluded.updated_at_utc,
                resolved_at_utc = excluded.resolved_at_utc;
            """;

        await ExecuteAsync(sql, cmd =>
        {
            cmd.Parameters.AddWithValue("$incident_id", incident.IncidentId);
            cmd.Parameters.AddWithValue("$incident_type", incident.IncidentType);
            cmd.Parameters.AddWithValue("$severity", incident.Severity);
            cmd.Parameters.AddWithValue("$status", incident.Status);
            cmd.Parameters.AddWithValue("$summary", incident.Summary);
            cmd.Parameters.AddWithValue("$evidence_json", incident.EvidenceJson);
            cmd.Parameters.AddWithValue("$opened_at_utc", incident.OpenedAtUtc.UtcDateTime.ToString("O"));
            cmd.Parameters.AddWithValue("$updated_at_utc", incident.UpdatedAtUtc.UtcDateTime.ToString("O"));
            cmd.Parameters.AddWithValue("$resolved_at_utc", incident.ResolvedAtUtc?.UtcDateTime.ToString("O") ?? (object)DBNull.Value);
        }, cancellationToken);
    }

    public async Task ResolveIncidentAsync(string incidentId, string resolutionSummary, CancellationToken cancellationToken)
    {
        const string sql = """
            UPDATE governance_incidents
            SET status = 'resolved',
                summary = $summary,
                updated_at_utc = $updated_at_utc,
                resolved_at_utc = $resolved_at_utc
            WHERE incident_id = $incident_id;
            """;

        var now = DateTimeOffset.UtcNow;
        await ExecuteAsync(sql, cmd =>
        {
            cmd.Parameters.AddWithValue("$incident_id", incidentId);
            cmd.Parameters.AddWithValue("$summary", resolutionSummary);
            cmd.Parameters.AddWithValue("$updated_at_utc", now.UtcDateTime.ToString("O"));
            cmd.Parameters.AddWithValue("$resolved_at_utc", now.UtcDateTime.ToString("O"));
        }, cancellationToken);
    }

    public async Task<IReadOnlyList<GovernanceEvent>> ListEventsAsync(string? track, int limit, CancellationToken cancellationToken)
    {
        var results = new List<GovernanceEvent>();
        var sql = string.IsNullOrWhiteSpace(track)
            ? "SELECT track, event_name, severity, result, skill_name, entity_type, entity_id, correlation_id, trace_id, duration_ms, ts_utc, payload_json FROM governance_events ORDER BY id DESC LIMIT $limit;"
            : "SELECT track, event_name, severity, result, skill_name, entity_type, entity_id, correlation_id, trace_id, duration_ms, ts_utc, payload_json FROM governance_events WHERE track = $track ORDER BY id DESC LIMIT $limit;";

        await QueryAsync(sql, cmd =>
        {
            cmd.Parameters.AddWithValue("$limit", Math.Clamp(limit, 1, 1000));
            if (!string.IsNullOrWhiteSpace(track))
            {
                cmd.Parameters.AddWithValue("$track", track.Trim());
            }
        }, reader =>
        {
            results.Add(new GovernanceEvent(
                reader.GetString(0),
                reader.GetString(1),
                reader.GetString(2),
                reader.GetString(3),
                reader.IsDBNull(4) ? null : reader.GetString(4),
                reader.IsDBNull(5) ? null : reader.GetString(5),
                reader.IsDBNull(6) ? null : reader.GetString(6),
                reader.IsDBNull(7) ? null : reader.GetString(7),
                reader.IsDBNull(8) ? null : reader.GetString(8),
                reader.IsDBNull(9) ? null : reader.GetInt64(9),
                DateTimeOffset.Parse(reader.GetString(10)),
                reader.GetString(11)));
        }, cancellationToken);

        return results;
    }

    public async Task<IReadOnlyList<GovernanceDecision>> ListDecisionsAsync(int limit, CancellationToken cancellationToken)
    {
        var list = new List<GovernanceDecision>();
        const string sql = """
            SELECT decision_id, decision_type, severity, summary, skill_name, entity_type, entity_id, metadata_json, ts_utc
            FROM governance_decisions
            ORDER BY id DESC
            LIMIT $limit;
            """;
        await QueryAsync(sql, cmd => cmd.Parameters.AddWithValue("$limit", Math.Clamp(limit, 1, 1000)), reader =>
        {
            list.Add(new GovernanceDecision(
                reader.GetString(0),
                reader.GetString(1),
                reader.GetString(2),
                reader.GetString(3),
                reader.IsDBNull(4) ? null : reader.GetString(4),
                reader.IsDBNull(5) ? null : reader.GetString(5),
                reader.IsDBNull(6) ? null : reader.GetString(6),
                reader.GetString(7),
                DateTimeOffset.Parse(reader.GetString(8))));
        }, cancellationToken);
        return list;
    }

    public async Task<IReadOnlyList<ActionExecution>> ListActionsAsync(int limit, CancellationToken cancellationToken)
    {
        var list = new List<ActionExecution>();
        const string sql = """
            SELECT action_id, action_type, severity, success, requires_approval, summary, output_json, ts_utc
            FROM governance_actions
            ORDER BY id DESC
            LIMIT $limit;
            """;
        await QueryAsync(sql, cmd => cmd.Parameters.AddWithValue("$limit", Math.Clamp(limit, 1, 1000)), reader =>
        {
            list.Add(new ActionExecution(
                reader.GetString(0),
                reader.GetString(1),
                reader.GetString(2),
                reader.GetInt64(3) == 1,
                reader.GetInt64(4) == 1,
                reader.GetString(5),
                reader.GetString(6),
                DateTimeOffset.Parse(reader.GetString(7))));
        }, cancellationToken);
        return list;
    }

    public async Task<IReadOnlyList<IncidentState>> ListIncidentsAsync(bool onlyOpen, int limit, CancellationToken cancellationToken)
    {
        var list = new List<IncidentState>();
        var sql = onlyOpen
            ? "SELECT incident_id, incident_type, severity, status, summary, evidence_json, opened_at_utc, updated_at_utc, resolved_at_utc FROM governance_incidents WHERE status <> 'resolved' ORDER BY updated_at_utc DESC LIMIT $limit;"
            : "SELECT incident_id, incident_type, severity, status, summary, evidence_json, opened_at_utc, updated_at_utc, resolved_at_utc FROM governance_incidents ORDER BY updated_at_utc DESC LIMIT $limit;";
        await QueryAsync(sql, cmd => cmd.Parameters.AddWithValue("$limit", Math.Clamp(limit, 1, 1000)), reader =>
        {
            list.Add(new IncidentState(
                reader.GetString(0),
                reader.GetString(1),
                reader.GetString(2),
                reader.GetString(3),
                reader.GetString(4),
                reader.GetString(5),
                DateTimeOffset.Parse(reader.GetString(6)),
                DateTimeOffset.Parse(reader.GetString(7)),
                reader.IsDBNull(8) ? null : DateTimeOffset.Parse(reader.GetString(8))));
        }, cancellationToken);
        return list;
    }

    public async Task<GovernanceStatusSnapshot> GetStatusSnapshotAsync(CancellationToken cancellationToken)
    {
        var now = DateTimeOffset.UtcNow;
        var since = now.AddHours(-24).UtcDateTime.ToString("O");
        var open = await ScalarIntAsync("SELECT COUNT(*) FROM governance_incidents WHERE status <> 'resolved';", cancellationToken);
        var critical = await ScalarIntAsync("SELECT COUNT(*) FROM governance_incidents WHERE status <> 'resolved' AND severity = 'critical';", cancellationToken);
        var decisions24h = await ScalarIntAsync("SELECT COUNT(*) FROM governance_decisions WHERE ts_utc >= $since;", cancellationToken, ("$since", since));
        var actions24h = await ScalarIntAsync("SELECT COUNT(*) FROM governance_actions WHERE ts_utc >= $since;", cancellationToken, ("$since", since));
        var failed24h = await ScalarIntAsync("SELECT COUNT(*) FROM governance_actions WHERE ts_utc >= $since AND success = 0;", cancellationToken, ("$since", since));
        var resolved24h = await ScalarIntAsync("SELECT COUNT(*) FROM governance_incidents WHERE resolved_at_utc >= $since;", cancellationToken, ("$since", since));
        var opened24h = await ScalarIntAsync("SELECT COUNT(*) FROM governance_incidents WHERE opened_at_utc >= $since;", cancellationToken, ("$since", since));
        var rate = opened24h == 0 ? 1.0 : Math.Clamp((double)resolved24h / opened24h, 0, 1);
        return new GovernanceStatusSnapshot(now, open, critical, decisions24h, actions24h, failed24h, rate);
    }

    public async Task AppendTuningChangeAsync(TuningChangeRecord change, CancellationToken cancellationToken)
    {
        const string sql = """
            INSERT INTO governance_tuning_changes
            (change_id, parameter_name, scope, before_value, after_value, reason, impact_expectation, ts_utc)
            VALUES
            ($change_id, $parameter_name, $scope, $before_value, $after_value, $reason, $impact_expectation, $ts_utc);
            """;

        await ExecuteAsync(sql, cmd =>
        {
            cmd.Parameters.AddWithValue("$change_id", change.ChangeId);
            cmd.Parameters.AddWithValue("$parameter_name", change.ParameterName);
            cmd.Parameters.AddWithValue("$scope", change.Scope);
            cmd.Parameters.AddWithValue("$before_value", change.BeforeValue);
            cmd.Parameters.AddWithValue("$after_value", change.AfterValue);
            cmd.Parameters.AddWithValue("$reason", change.Reason);
            cmd.Parameters.AddWithValue("$impact_expectation", change.ImpactExpectation);
            cmd.Parameters.AddWithValue("$ts_utc", change.TimestampUtc.UtcDateTime.ToString("O"));
        }, cancellationToken);
    }

    public async Task<IReadOnlyList<TuningChangeRecord>> ListTuningChangesAsync(int limit, CancellationToken cancellationToken)
    {
        var list = new List<TuningChangeRecord>();
        const string sql = """
            SELECT change_id, parameter_name, scope, before_value, after_value, reason, impact_expectation, ts_utc
            FROM governance_tuning_changes
            ORDER BY id DESC
            LIMIT $limit;
            """;
        await QueryAsync(sql, cmd => cmd.Parameters.AddWithValue("$limit", Math.Clamp(limit, 1, 1000)), reader =>
        {
            list.Add(new TuningChangeRecord(
                reader.GetString(0),
                reader.GetString(1),
                reader.GetString(2),
                reader.GetString(3),
                reader.GetString(4),
                reader.GetString(5),
                reader.GetString(6),
                DateTimeOffset.Parse(reader.GetString(7))));
        }, cancellationToken);
        return list;
    }

    private void EnsureSchema()
    {
        using var connection = OpenConnection();
        using var cmd = connection.CreateCommand();
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS governance_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                track TEXT NOT NULL,
                event_name TEXT NOT NULL,
                severity TEXT NOT NULL,
                result TEXT NOT NULL,
                skill_name TEXT NULL,
                entity_type TEXT NULL,
                entity_id TEXT NULL,
                correlation_id TEXT NULL,
                trace_id TEXT NULL,
                duration_ms INTEGER NULL,
                ts_utc TEXT NOT NULL,
                payload_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS governance_decisions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                decision_id TEXT NOT NULL UNIQUE,
                decision_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                summary TEXT NOT NULL,
                skill_name TEXT NULL,
                entity_type TEXT NULL,
                entity_id TEXT NULL,
                metadata_json TEXT NOT NULL,
                ts_utc TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS governance_actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action_id TEXT NOT NULL UNIQUE,
                action_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                success INTEGER NOT NULL,
                requires_approval INTEGER NOT NULL,
                summary TEXT NOT NULL,
                output_json TEXT NOT NULL,
                ts_utc TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS governance_incidents (
                incident_id TEXT PRIMARY KEY,
                incident_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL,
                summary TEXT NOT NULL,
                evidence_json TEXT NOT NULL,
                opened_at_utc TEXT NOT NULL,
                updated_at_utc TEXT NOT NULL,
                resolved_at_utc TEXT NULL
            );

            CREATE TABLE IF NOT EXISTS governance_tuning_changes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                change_id TEXT NOT NULL UNIQUE,
                parameter_name TEXT NOT NULL,
                scope TEXT NOT NULL,
                before_value TEXT NOT NULL,
                after_value TEXT NOT NULL,
                reason TEXT NOT NULL,
                impact_expectation TEXT NOT NULL,
                ts_utc TEXT NOT NULL
            );
            """;
        cmd.ExecuteNonQuery();
    }

    private SqliteConnection OpenConnection()
    {
        var connection = new SqliteConnection($"Data Source={_dbPath}");
        connection.Open();
        return connection;
    }

    private async Task ExecuteAsync(string sql, Action<SqliteCommand> bind, CancellationToken cancellationToken)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            await using var connection = OpenConnection();
            await using var cmd = connection.CreateCommand();
            cmd.CommandText = sql;
            bind(cmd);
            await cmd.ExecuteNonQueryAsync(cancellationToken);
        }
        finally
        {
            _mutex.Release();
        }
    }

    private async Task QueryAsync(string sql, Action<SqliteCommand> bind, Action<SqliteDataReader> readRow, CancellationToken cancellationToken)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            await using var connection = OpenConnection();
            await using var cmd = connection.CreateCommand();
            cmd.CommandText = sql;
            bind(cmd);
            await using var reader = await cmd.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                readRow(reader);
            }
        }
        finally
        {
            _mutex.Release();
        }
    }

    private async Task<int> ScalarIntAsync(string sql, CancellationToken cancellationToken, params (string Name, object Value)[] parameters)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            await using var connection = OpenConnection();
            await using var cmd = connection.CreateCommand();
            cmd.CommandText = sql;
            foreach (var (name, value) in parameters)
            {
                cmd.Parameters.AddWithValue(name, value);
            }
            var result = await cmd.ExecuteScalarAsync(cancellationToken);
            return Convert.ToInt32(result ?? 0);
        }
        finally
        {
            _mutex.Release();
        }
    }
}
