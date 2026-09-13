using System.Globalization;
using System.Text;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Domain.Content;
using Microsoft.Extensions.Options;
using Npgsql;

namespace AchadinhosBot.Next.Infrastructure.Storage;

/// <summary>
/// PostgreSQL implementation of the content calendar store. The claim operation is deliberately
/// performed in one UPDATE ... RETURNING statement so separate API/worker processes cannot claim
/// the same planned item.
/// </summary>
public sealed class PostgresContentCalendarStore : IContentCalendarStore
{
    private const string Columns = "id, scheduled_at, post_type, source_input, offer_context, reference_url, reference_caption, reference_media_url, offer_url, keyword, generated_caption, hashtags, media_url, auto_publish, status, draft_id, published_media_id, error, attempts, last_attempt_at, processing_execution_id, processing_claimed_at, created_at, updated_at";
    private readonly string _connectionString;

    public PostgresContentCalendarStore(IOptions<ContentCalendarStorageOptions> options)
        : this(options.Value.ConnectionString ?? throw new InvalidOperationException("ContentCalendarStorage.ConnectionString is required for PostgreSQL."))
    {
    }

    public PostgresContentCalendarStore(string connectionString)
    {
        if (string.IsNullOrWhiteSpace(connectionString))
        {
            throw new ArgumentException("A PostgreSQL connection string is required.", nameof(connectionString));
        }

        _connectionString = connectionString;
    }

    public async Task<IReadOnlyList<ContentCalendarItem>> ListAsync(CancellationToken ct)
    {
        const string sql = $"SELECT {Columns} FROM achadinhos.content_calendar_items ORDER BY scheduled_at, created_at;";
        await using var connection = await OpenAsync(ct);
        await using var command = new NpgsqlCommand(sql, connection);
        await using var reader = await command.ExecuteReaderAsync(ct);
        var items = new List<ContentCalendarItem>();
        while (await reader.ReadAsync(ct)) items.Add(ReadItem(reader));
        return items;
    }

    public async Task<ContentCalendarItem?> GetAsync(string id, CancellationToken ct)
    {
        const string sql = $"SELECT {Columns} FROM achadinhos.content_calendar_items WHERE id = @id;";
        await using var connection = await OpenAsync(ct);
        await using var command = new NpgsqlCommand(sql, connection);
        command.Parameters.AddWithValue("id", id);
        await using var reader = await command.ExecuteReaderAsync(ct);
        return await reader.ReadAsync(ct) ? ReadItem(reader) : null;
    }

    public async Task SaveAsync(ContentCalendarItem item, CancellationToken ct)
    {
        const string sql = @"
INSERT INTO achadinhos.content_calendar_items (
    id, scheduled_at, post_type, source_input, offer_context, reference_url, reference_caption, reference_media_url,
    offer_url, keyword, generated_caption, hashtags, media_url, auto_publish, status, draft_id, published_media_id,
    error, attempts, last_attempt_at, processing_execution_id, processing_claimed_at, created_at, updated_at)
VALUES (
    @id, @scheduledAt, @postType, @sourceInput, @offerContext, @referenceUrl, @referenceCaption, @referenceMediaUrl,
    @offerUrl, @keyword, @generatedCaption, @hashtags, @mediaUrl, @autoPublish, @status, @draftId, @publishedMediaId,
    @error, @attempts, @lastAttemptAt, @processingExecutionId, @processingClaimedAt, @createdAt, @updatedAt)
ON CONFLICT (id) DO UPDATE SET
    scheduled_at = EXCLUDED.scheduled_at, post_type = EXCLUDED.post_type, source_input = EXCLUDED.source_input,
    offer_context = EXCLUDED.offer_context, reference_url = EXCLUDED.reference_url, reference_caption = EXCLUDED.reference_caption,
    reference_media_url = EXCLUDED.reference_media_url, offer_url = EXCLUDED.offer_url, keyword = EXCLUDED.keyword,
    generated_caption = EXCLUDED.generated_caption, hashtags = EXCLUDED.hashtags, media_url = EXCLUDED.media_url,
    auto_publish = EXCLUDED.auto_publish, status = EXCLUDED.status, draft_id = EXCLUDED.draft_id,
    published_media_id = EXCLUDED.published_media_id, error = EXCLUDED.error, attempts = EXCLUDED.attempts,
    last_attempt_at = EXCLUDED.last_attempt_at, processing_execution_id = EXCLUDED.processing_execution_id,
    processing_claimed_at = EXCLUDED.processing_claimed_at, created_at = EXCLUDED.created_at, updated_at = EXCLUDED.updated_at;";

        await using var connection = await OpenAsync(ct);
        await using var command = new NpgsqlCommand(sql, connection);
        AddItemParameters(command, item);
        await command.ExecuteNonQueryAsync(ct);
    }

    public async Task<ContentCalendarItem?> TryClaimDueAsync(string id, string executionId, DateTimeOffset now, int maxAttempts, CancellationToken ct)
    {
        // The WHERE predicate is the concurrency boundary. PostgreSQL row locking makes a second
        // contender re-check the status after the first UPDATE commits, so it returns no row.
        var sql = $@"
UPDATE achadinhos.content_calendar_items
SET status = 'processing',
    processing_execution_id = @executionId,
    processing_claimed_at = @now,
    attempts = attempts + 1,
    last_attempt_at = @now,
    updated_at = @now
WHERE id = @id
  AND scheduled_at <= @now
  AND attempts < @maxAttempts
  AND status = 'planned'
RETURNING {Columns};";

        await using var connection = await OpenAsync(ct);
        await using var command = new NpgsqlCommand(sql, connection);
        command.Parameters.AddWithValue("id", id);
        command.Parameters.AddWithValue("executionId", executionId);
        command.Parameters.AddWithValue("now", now);
        command.Parameters.AddWithValue("maxAttempts", maxAttempts);
        await using var reader = await command.ExecuteReaderAsync(ct);
        return await reader.ReadAsync(ct) ? ReadItem(reader) : null;
    }

    public async Task DeleteAsync(string id, CancellationToken ct)
    {
        const string sql = "DELETE FROM achadinhos.content_calendar_items WHERE id = @id;";
        await using var connection = await OpenAsync(ct);
        await using var command = new NpgsqlCommand(sql, connection);
        command.Parameters.AddWithValue("id", id);
        await command.ExecuteNonQueryAsync(ct);
    }

    public async Task<string> ExportCsvAsync(CancellationToken ct)
    {
        var items = await ListAsync(ct);
        var sb = new StringBuilder();
        sb.AppendLine("Id,ScheduledAt,PostType,SourceInput,OfferContext,ReferenceUrl,ReferenceCaption,ReferenceMediaUrl,OfferUrl,Keyword,GeneratedCaption,Hashtags,MediaUrl,AutoPublish,Status,DraftId,PublishedMediaId,Error,Attempts,LastAttemptAt,CreatedAt,UpdatedAt,ProcessingExecutionId,ProcessingClaimedAt");
        foreach (var item in items)
        {
            var values = new[] { item.Id, Date(item.ScheduledAt), item.PostType, item.SourceInput, item.OfferContext, item.ReferenceUrl, item.ReferenceCaption, item.ReferenceMediaUrl, item.OfferUrl, item.Keyword, item.GeneratedCaption, item.Hashtags, item.MediaUrl, item.AutoPublish ? "true" : "false", item.Status, item.DraftId ?? string.Empty, item.PublishedMediaId ?? string.Empty, item.Error ?? string.Empty, item.Attempts.ToString(CultureInfo.InvariantCulture), NullableDate(item.LastAttemptAt), Date(item.CreatedAt), Date(item.UpdatedAt), item.ProcessingExecutionId ?? string.Empty, NullableDate(item.ProcessingClaimedAt) };
            sb.AppendLine(string.Join(',', values.Select(EscapeCsv)));
        }
        return sb.ToString();
    }

    /// <summary>
    /// Imports one immutable CSV snapshot exactly once. This is intentionally separate from
    /// normal startup: callers must opt in after pausing calendar processing for a cutover.
    /// </summary>
    public async Task<bool> ImportCsvSnapshotAsync(
        IReadOnlyList<ContentCalendarItem> items,
        string sourceSha256,
        CancellationToken ct)
    {
        const string migrationName = "content-calendar-csv-v1";
        const string upsert = @"
INSERT INTO achadinhos.content_calendar_items (
    id, scheduled_at, post_type, source_input, offer_context, reference_url, reference_caption, reference_media_url,
    offer_url, keyword, generated_caption, hashtags, media_url, auto_publish, status, draft_id, published_media_id,
    error, attempts, last_attempt_at, processing_execution_id, processing_claimed_at, created_at, updated_at)
VALUES (
    @id, @scheduledAt, @postType, @sourceInput, @offerContext, @referenceUrl, @referenceCaption, @referenceMediaUrl,
    @offerUrl, @keyword, @generatedCaption, @hashtags, @mediaUrl, @autoPublish, @status, @draftId, @publishedMediaId,
    @error, @attempts, @lastAttemptAt, @processingExecutionId, @processingClaimedAt, @createdAt, @updatedAt)
ON CONFLICT (id) DO UPDATE SET
    scheduled_at = EXCLUDED.scheduled_at, post_type = EXCLUDED.post_type, source_input = EXCLUDED.source_input,
    offer_context = EXCLUDED.offer_context, reference_url = EXCLUDED.reference_url, reference_caption = EXCLUDED.reference_caption,
    reference_media_url = EXCLUDED.reference_media_url, offer_url = EXCLUDED.offer_url, keyword = EXCLUDED.keyword,
    generated_caption = EXCLUDED.generated_caption, hashtags = EXCLUDED.hashtags, media_url = EXCLUDED.media_url,
    auto_publish = EXCLUDED.auto_publish, status = EXCLUDED.status, draft_id = EXCLUDED.draft_id,
    published_media_id = EXCLUDED.published_media_id, error = EXCLUDED.error, attempts = EXCLUDED.attempts,
    last_attempt_at = EXCLUDED.last_attempt_at, processing_execution_id = EXCLUDED.processing_execution_id,
    processing_claimed_at = EXCLUDED.processing_claimed_at, created_at = EXCLUDED.created_at, updated_at = EXCLUDED.updated_at;";

        await using var connection = await OpenAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(System.Data.IsolationLevel.Serializable, ct);
        await using (var lockCommand = new NpgsqlCommand("SELECT pg_advisory_xact_lock(hashtext('achadinhos:content-calendar:csv-v1'));", connection, transaction))
        {
            await lockCommand.ExecuteNonQueryAsync(ct);
        }

        await using (var check = new NpgsqlCommand("SELECT source_sha256 FROM achadinhos.data_migrations WHERE name = @name;", connection, transaction))
        {
            check.Parameters.AddWithValue("name", migrationName);
            var existingHash = await check.ExecuteScalarAsync(ct) as string;
            if (existingHash is not null)
            {
                if (!string.Equals(existingHash, sourceSha256, StringComparison.Ordinal))
                {
                    throw new InvalidOperationException("A migração do calendário já foi aplicada com uma origem CSV diferente. Não é seguro reaplicá-la.");
                }

                await transaction.CommitAsync(ct);
                return false;
            }
        }

        foreach (var item in items)
        {
            await using var command = new NpgsqlCommand(upsert, connection, transaction);
            AddItemParameters(command, item);
            await command.ExecuteNonQueryAsync(ct);
        }

        await using (var marker = new NpgsqlCommand(
                         "INSERT INTO achadinhos.data_migrations (name, source_sha256, row_count) VALUES (@name, @hash, @count);",
                         connection,
                         transaction))
        {
            marker.Parameters.AddWithValue("name", migrationName);
            marker.Parameters.AddWithValue("hash", sourceSha256);
            marker.Parameters.AddWithValue("count", items.Count);
            await marker.ExecuteNonQueryAsync(ct);
        }

        await transaction.CommitAsync(ct);
        return true;
    }

    private async Task<NpgsqlConnection> OpenAsync(CancellationToken ct)
    {
        var connection = new NpgsqlConnection(_connectionString);
        await connection.OpenAsync(ct);
        return connection;
    }

    private static void AddItemParameters(NpgsqlCommand command, ContentCalendarItem item)
    {
        command.Parameters.AddWithValue("id", item.Id);
        command.Parameters.AddWithValue("scheduledAt", item.ScheduledAt);
        command.Parameters.AddWithValue("postType", item.PostType);
        command.Parameters.AddWithValue("sourceInput", item.SourceInput);
        command.Parameters.AddWithValue("offerContext", item.OfferContext);
        command.Parameters.AddWithValue("referenceUrl", item.ReferenceUrl);
        command.Parameters.AddWithValue("referenceCaption", item.ReferenceCaption);
        command.Parameters.AddWithValue("referenceMediaUrl", item.ReferenceMediaUrl);
        command.Parameters.AddWithValue("offerUrl", item.OfferUrl);
        command.Parameters.AddWithValue("keyword", item.Keyword);
        command.Parameters.AddWithValue("generatedCaption", item.GeneratedCaption);
        command.Parameters.AddWithValue("hashtags", item.Hashtags);
        command.Parameters.AddWithValue("mediaUrl", item.MediaUrl);
        command.Parameters.AddWithValue("autoPublish", item.AutoPublish);
        command.Parameters.AddWithValue("status", item.Status);
        AddNullable(command, "draftId", item.DraftId);
        AddNullable(command, "publishedMediaId", item.PublishedMediaId);
        AddNullable(command, "error", item.Error);
        command.Parameters.AddWithValue("attempts", item.Attempts);
        AddNullable(command, "lastAttemptAt", item.LastAttemptAt);
        AddNullable(command, "processingExecutionId", item.ProcessingExecutionId);
        AddNullable(command, "processingClaimedAt", item.ProcessingClaimedAt);
        command.Parameters.AddWithValue("createdAt", item.CreatedAt);
        command.Parameters.AddWithValue("updatedAt", item.UpdatedAt);
    }

    private static void AddNullable(NpgsqlCommand command, string name, object? value) => command.Parameters.AddWithValue(name, value ?? DBNull.Value);

    private static ContentCalendarItem ReadItem(NpgsqlDataReader row) => new()
    {
        Id = row.GetString(0), ScheduledAt = row.GetFieldValue<DateTimeOffset>(1), PostType = row.GetString(2),
        SourceInput = row.GetString(3), OfferContext = row.GetString(4), ReferenceUrl = row.GetString(5),
        ReferenceCaption = row.GetString(6), ReferenceMediaUrl = row.GetString(7), OfferUrl = row.GetString(8),
        Keyword = row.GetString(9), GeneratedCaption = row.GetString(10), Hashtags = row.GetString(11), MediaUrl = row.GetString(12),
        AutoPublish = row.GetBoolean(13), Status = row.GetString(14), DraftId = NullableString(row, 15),
        PublishedMediaId = NullableString(row, 16), Error = NullableString(row, 17), Attempts = row.GetInt32(18),
        LastAttemptAt = NullableDate(row, 19), ProcessingExecutionId = NullableString(row, 20),
        ProcessingClaimedAt = NullableDate(row, 21), CreatedAt = row.GetFieldValue<DateTimeOffset>(22), UpdatedAt = row.GetFieldValue<DateTimeOffset>(23)
    };

    private static string? NullableString(NpgsqlDataReader row, int ordinal) => row.IsDBNull(ordinal) ? null : row.GetString(ordinal);
    private static DateTimeOffset? NullableDate(NpgsqlDataReader row, int ordinal) => row.IsDBNull(ordinal) ? null : row.GetFieldValue<DateTimeOffset>(ordinal);
    private static string Date(DateTimeOffset value) => value.ToString("O", CultureInfo.InvariantCulture);
    private static string NullableDate(DateTimeOffset? value) => value?.ToString("O", CultureInfo.InvariantCulture) ?? string.Empty;
    private static string EscapeCsv(string value) => value.Contains(',') || value.Contains('"') || value.Contains('\n') || value.Contains('\r') ? $"\"{value.Replace("\"", "\"\"")}\"" : value;
}
