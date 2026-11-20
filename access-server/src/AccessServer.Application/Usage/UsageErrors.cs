using AccessServer.Application.Common;

namespace AccessServer.Application.Usage;

public static class UsageErrors
{
    public static readonly Error BatchTooLarge =
        Error.Validation("USAGE_BATCH_TOO_LARGE",
            $"Bitta hisobotda ko'pi bilan {RecordUsageHandler.MaxBatchSize} ta oyna bo'lishi mumkin.");

    public static readonly Error RangeInvalid =
        Error.Validation("USAGE_RANGE_INVALID",
            "Davr noto'g'ri: from va to ISO-8601 vaqt bo'lishi (masalan 2026-11-01T00:00:00Z), "
            + $"from < to va oraliq {GetUsageHandler.MaxRangeDays} kundan oshmasligi kerak.");
}
