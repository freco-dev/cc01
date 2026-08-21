namespace AccessServer.Domain.Entities;

public abstract class Entity
{
    public int Id { get; set; }

    // DateTime emas, DateTimeOffset: server va baza turli zonalarda bo'lishi
    // mumkin, offset saqlanmasa vaqt noaniq bo'lib qoladi.
    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset UpdatedAt { get; set; }
}
