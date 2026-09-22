namespace RegulatedAi.Core.Contracts;

/// <summary>
/// Evidence is classified by tag rather than by parsing document prose. Risk evaluation asks
/// "is there a trusted, unexpired document carrying this tag?" — a structured question — instead
/// of asking a language model to interpret text it does not control.
/// </summary>
public static class EvidenceTags
{
    /// <summary>Marks the document that *states* the evidence requirements for payment-data vendors.</summary>
    public const string PaymentVendorRequirements = "payment_vendor_requirements";

    /// <summary>Marks the document that states who may approve a vendor.</summary>
    public const string VendorApprovalPolicy = "vendor_approval_policy";

    /// <summary>Marks the governing contract for the subject, cited when a clause is absent.</summary>
    public const string VendorContract = "vendor_contract";

    // --- Requirement-satisfying tags -------------------------------------------------------

    public const string Soc2Report = "soc2_report";
    public const string DataRetentionSchedule = "data_retention_schedule";
    public const string BreachNotificationClause = "breach_notification_clause";
}
