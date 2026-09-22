using System.Text.Json;
using RegulatedAi.Api.Contracts;
using RegulatedAi.Core.Contracts;

namespace RegulatedAi.Api.UnitTests;

/// <summary>
/// The published JSON contract, asserted against the service's real serializer options.
/// </summary>
/// <remarks>
/// These exist because of a bug that every other test missed. The engine's enums each carried a
/// <c>[JsonConverter]</c> giving the contracted wire form, but a global
/// <c>JsonStringEnumConverter</c> in <c>JsonSerializerOptions.Converters</c> took precedence over
/// them — converters in that collection outrank type-level attributes — so
/// <c>blocked_pending_approval</c> shipped as <c>blockedPendingApproval</c>. Nothing threw.
/// Controller tests asserted the enum value, not the string a consumer receives.
/// The lesson: if a serialized form is part of the contract, assert the serialized form.
/// </remarks>
public sealed class WireContractTests
{
    private static readonly JsonSerializerOptions Options = RegulatedAiJsonOptions.Create();

    private static JsonElement Serialize(WorkflowResult result) =>
        JsonDocument.Parse(JsonSerializer.Serialize(result, Options)).RootElement;

    private static WorkflowResult Result(
        RiskLevel riskLevel = RiskLevel.High,
        ActionStatus actionStatus = ActionStatus.BlockedPendingApproval) => new()
    {
        RiskLevel = riskLevel,
        Recommendation = "Do not approve yet.",
        Reasons = new[] { "No SOC 2 evidence found." },
        Citations = new[] { new Citation("policy-a-002", "Payment data vendors require...") },
        MissingEvidence = new[] { "SOC 2 report" },
        RequiresApproval = true,
        ActionStatus = actionStatus,
        ActionDetail = "No approver was referenced.",
        QuarantinedEvidence = new[]
        {
            new QuarantinedEvidence("evidence-a-666", new[] { "ignore-previous-instructions" }),
        },
        CorrelationId = "corr-1",
    };

    // -------------------------------------------------------------------------------------------
    // Enum wire forms — the contract the brief specifies
    // -------------------------------------------------------------------------------------------

    [Theory]
    [InlineData(ActionStatus.NotRequested, "not_requested")]
    [InlineData(ActionStatus.Executed, "executed")]
    [InlineData(ActionStatus.BlockedPendingApproval, "blocked_pending_approval")]
    [InlineData(ActionStatus.DeniedInsufficientRole, "denied_insufficient_role")]
    [InlineData(ActionStatus.UnsupportedAction, "unsupported_action")]
    public void Action_status_serializes_to_its_contracted_snake_case_form(
        ActionStatus status,
        string expected)
    {
        var json = Serialize(Result(actionStatus: status));

        Assert.Equal(expected, json.GetProperty("actionStatus").GetString());
    }

    [Theory]
    [InlineData(RiskLevel.Low, "low")]
    [InlineData(RiskLevel.Medium, "medium")]
    [InlineData(RiskLevel.High, "high")]
    public void Risk_level_serializes_to_its_contracted_lowercase_form(
        RiskLevel level,
        string expected)
    {
        var json = Serialize(Result(riskLevel: level));

        Assert.Equal(expected, json.GetProperty("riskLevel").GetString());
    }

    [Fact]
    public void Enums_serialize_as_strings_not_numbers()
    {
        var json = Serialize(Result());

        Assert.Equal(JsonValueKind.String, json.GetProperty("riskLevel").ValueKind);
        Assert.Equal(JsonValueKind.String, json.GetProperty("actionStatus").ValueKind);
    }

    [Theory]
    [InlineData("blocked_pending_approval", ActionStatus.BlockedPendingApproval)]
    [InlineData("executed", ActionStatus.Executed)]
    [InlineData("BLOCKED_PENDING_APPROVAL", ActionStatus.BlockedPendingApproval)]
    public void Action_status_round_trips_from_the_wire(string wire, ActionStatus expected) =>
        Assert.Equal(expected, JsonSerializer.Deserialize<ActionStatus>($"\"{wire}\"", Options));

    [Fact]
    public void An_unrecognised_action_status_on_the_wire_is_an_error() =>
        Assert.Throws<JsonException>(
            () => JsonSerializer.Deserialize<ActionStatus>("\"made_up_status\"", Options));

    [Fact]
    public void An_unrecognised_risk_level_on_the_wire_is_an_error() =>
        Assert.Throws<JsonException>(
            () => JsonSerializer.Deserialize<RiskLevel>("\"catastrophic\"", Options));

    // -------------------------------------------------------------------------------------------
    // Property names and ordering
    // -------------------------------------------------------------------------------------------

    [Theory]
    [InlineData("riskLevel")]
    [InlineData("recommendation")]
    [InlineData("reasons")]
    [InlineData("citations")]
    [InlineData("missingEvidence")]
    [InlineData("requiresApproval")]
    [InlineData("actionStatus")]
    [InlineData("quarantinedEvidence")]
    [InlineData("correlationId")]
    public void The_response_carries_the_contracted_property(string propertyName) =>
        Assert.True(
            Serialize(Result()).TryGetProperty(propertyName, out _),
            $"The response is missing the contracted property '{propertyName}'.");

    [Fact]
    public void Citations_use_documentId_and_snippet()
    {
        var citation = Serialize(Result()).GetProperty("citations").EnumerateArray().First();

        Assert.Equal("policy-a-002", citation.GetProperty("documentId").GetString());
        Assert.True(citation.TryGetProperty("snippet", out _));
    }

    /// <summary>
    /// Quarantining content and then echoing it back would be contradictory, so the reported shape
    /// carries the document id and the matched pattern names and nothing else.
    /// </summary>
    [Fact]
    public void Quarantined_evidence_reports_patterns_but_never_the_offending_text()
    {
        var quarantined = Serialize(Result())
            .GetProperty("quarantinedEvidence")
            .EnumerateArray()
            .First();

        Assert.Equal("evidence-a-666", quarantined.GetProperty("documentId").GetString());
        Assert.True(quarantined.TryGetProperty("matchedPatterns", out _));
        Assert.False(quarantined.TryGetProperty("snippet", out _));
        Assert.False(quarantined.TryGetProperty("text", out _));
    }

    [Fact]
    public void Property_names_are_camel_case()
    {
        var json = Serialize(Result());

        foreach (var property in json.EnumerateObject())
        {
            Assert.True(
                char.IsLower(property.Name[0]),
                $"'{property.Name}' is not camelCase.");
        }
    }

    /// <summary>
    /// The brief presents the response with the risk verdict first. Declaration order is
    /// serialization order, so this is worth pinning.
    /// </summary>
    [Fact]
    public void The_response_leads_with_the_risk_verdict()
    {
        var names = Serialize(Result()).EnumerateObject().Select(p => p.Name).ToArray();

        Assert.Equal("riskLevel", names[0]);
        Assert.Equal("recommendation", names[1]);
    }

    // -------------------------------------------------------------------------------------------
    // Nullable enums on the audit record
    // -------------------------------------------------------------------------------------------

    /// <summary>
    /// The audit record's enums are nullable, which is a separate serialization path — a
    /// per-type converter has to survive the <c>Nullable&lt;T&gt;</c> wrapper.
    /// </summary>
    [Fact]
    public void Nullable_enums_on_an_audit_event_use_the_same_wire_forms()
    {
        var auditEvent = new AuditEvent
        {
            TenantId = "tenant-a",
            UserId = "alice",
            Role = "analyst",
            EventType = AuditEventTypes.ActionBlockedPendingApproval,
            RiskLevel = RiskLevel.High,
            ActionStatus = ActionStatus.BlockedPendingApproval,
            CorrelationId = "corr-1",
        };

        var json = JsonDocument.Parse(JsonSerializer.Serialize(auditEvent, Options)).RootElement;

        Assert.Equal("high", json.GetProperty("riskLevel").GetString());
        Assert.Equal("blocked_pending_approval", json.GetProperty("actionStatus").GetString());
    }

    [Fact]
    public void Null_properties_are_omitted()
    {
        var auditEvent = new AuditEvent
        {
            TenantId = "tenant-a",
            UserId = "alice",
            Role = "analyst",
            EventType = AuditEventTypes.WorkflowRun,
            CorrelationId = "corr-1",
        };

        var json = JsonDocument.Parse(JsonSerializer.Serialize(auditEvent, Options)).RootElement;

        Assert.False(json.TryGetProperty("riskLevel", out _));
        Assert.False(json.TryGetProperty("actionStatus", out _));
        Assert.False(json.TryGetProperty("detail", out _));
    }

    /// <summary>
    /// Guards the fix directly: a global enum converter would silently outrank the per-type ones,
    /// so there must not be one.
    /// </summary>
    [Fact]
    public void The_service_registers_no_global_enum_converter() =>
        Assert.Empty(RegulatedAiJsonOptions.Create().Converters);
}
