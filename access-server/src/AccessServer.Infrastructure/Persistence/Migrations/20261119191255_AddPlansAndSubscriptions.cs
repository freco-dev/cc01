using System;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace AccessServer.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddPlansAndSubscriptions : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // ⚠️ Tartib qo'lda belgilangan: EF DropColumn'ni birinchi chiqaradi,
            // lekin tenants.plan backfill uchun kerak — u eng oxirida o'chiriladi.

            // 1) Tarif katalogi + seed (id 1–3; identity 100 dan boshlanadi).
            migrationBuilder.CreateTable(
                name: "plans",
                columns: table => new
                {
                    id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:IdentitySequenceOptions", "'100', '1', '', '', 'False', '1'")
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    code = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: false),
                    name = table.Column<string>(type: "character varying(40)", maxLength: 40, nullable: false),
                    max_subdomains = table.Column<int>(type: "integer", nullable: false),
                    max_tunnels = table.Column<int>(type: "integer", nullable: false),
                    max_conns_per_tunnel = table.Column<int>(type: "integer", nullable: false),
                    bandwidth_bps = table.Column<long>(type: "bigint", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_plans", x => x.id);
                    table.CheckConstraint("ck_plans_limits", "max_subdomains >= 1 AND max_tunnels >= 1 AND max_conns_per_tunnel >= 1 AND bandwidth_bps >= 0");
                });

            migrationBuilder.CreateIndex(
                name: "ix_plans_code",
                table: "plans",
                column: "code",
                unique: true);

            migrationBuilder.InsertData(
                table: "plans",
                columns: new[] { "id", "bandwidth_bps", "code", "created_at", "max_conns_per_tunnel", "max_subdomains", "max_tunnels", "name", "updated_at" },
                values: new object[,]
                {
                    { 1, 100000000L, "Free", new DateTimeOffset(new DateTime(2026, 11, 20, 0, 0, 0, 0, DateTimeKind.Unspecified), new TimeSpan(0, 0, 0, 0, 0)), 24, 1, 1, "Free", new DateTimeOffset(new DateTime(2026, 11, 20, 0, 0, 0, 0, DateTimeKind.Unspecified), new TimeSpan(0, 0, 0, 0, 0)) },
                    { 2, 1000000000L, "Pro", new DateTimeOffset(new DateTime(2026, 11, 20, 0, 0, 0, 0, DateTimeKind.Unspecified), new TimeSpan(0, 0, 0, 0, 0)), 128, 10, 10, "Pro", new DateTimeOffset(new DateTime(2026, 11, 20, 0, 0, 0, 0, DateTimeKind.Unspecified), new TimeSpan(0, 0, 0, 0, 0)) },
                    { 3, 0L, "Enterprise", new DateTimeOffset(new DateTime(2026, 11, 20, 0, 0, 0, 0, DateTimeKind.Unspecified), new TimeSpan(0, 0, 0, 0, 0)), 1024, 100, 100, "Enterprise", new DateTimeOffset(new DateTime(2026, 11, 20, 0, 0, 0, 0, DateTimeKind.Unspecified), new TimeSpan(0, 0, 0, 0, 0)) }
                });

            // 2) Obunalar: har bir tenantda bitta qator.
            migrationBuilder.CreateTable(
                name: "subscriptions",
                columns: table => new
                {
                    id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    tenant_id = table.Column<int>(type: "integer", nullable: false),
                    plan_id = table.Column<int>(type: "integer", nullable: false),
                    status = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: false),
                    period_start = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    period_end = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    xmin = table.Column<uint>(type: "xid", rowVersion: true, nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_subscriptions", x => x.id);
                    table.CheckConstraint("ck_subscriptions_period", "period_end IS NULL OR period_end > period_start");
                    table.ForeignKey(
                        name: "fk_subscriptions_plans_plan_id",
                        column: x => x.plan_id,
                        principalTable: "plans",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "fk_subscriptions_tenants_tenant_id",
                        column: x => x.tenant_id,
                        principalTable: "tenants",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "ix_subscriptions_plan_id",
                table: "subscriptions",
                column: "plan_id");

            migrationBuilder.CreateIndex(
                name: "ix_subscriptions_tenant_id",
                table: "subscriptions",
                column: "tenant_id",
                unique: true);

            // 3) Audit.
            migrationBuilder.CreateTable(
                name: "audit_events",
                columns: table => new
                {
                    id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    tenant_id = table.Column<int>(type: "integer", nullable: true),
                    user_id = table.Column<int>(type: "integer", nullable: true),
                    actor = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    action = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    target = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    ip = table.Column<string>(type: "character varying(45)", maxLength: 45, nullable: true),
                    metadata = table.Column<string>(type: "jsonb", nullable: true),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_audit_events", x => x.id);
                });

            migrationBuilder.CreateIndex(
                name: "ix_audit_events_tenant_id_created_at",
                table: "audit_events",
                columns: new[] { "tenant_id", "created_at" });

            // 4) Backfill: mavjud tenantlar o'z tarifini saqlaydi. Noma'lum
            //    qiymat (qo'lda yozilgan bo'lsa) Free'ga tushadi.
            migrationBuilder.Sql(
                """
                INSERT INTO subscriptions (tenant_id, plan_id, status, period_start, period_end, created_at, updated_at)
                SELECT t.id, p.id, 'Active', t.created_at, NULL, now(), now()
                FROM tenants t
                JOIN plans p ON p.code = CASE WHEN t.plan IN ('Free', 'Pro', 'Enterprise') THEN t.plan ELSE 'Free' END;
                """);

            // 5) Eski ustun — faqat backfill'dan keyin.
            migrationBuilder.DropColumn(
                name: "plan",
                table: "tenants");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            // ⚠️ Down obuna davri, holati va audit yozuvlarini YO'QOTADI —
            // faqat HOZIR AMALDA bo'lgan tarif kodi tenants.plan'ga qaytariladi.

            // 1) Ustun vaqtincha default bilan: mavjud qatorlar NOT NULL'ni buzmaydi.
            migrationBuilder.AddColumn<string>(
                name: "plan",
                table: "tenants",
                type: "character varying(20)",
                maxLength: 20,
                nullable: false,
                defaultValue: "Free");

            // 2) Qiymatlarni obunalardan tiklash — EffectivePlanResolver
            //    qoidasi bilan: faqat aktiv va muddati o'tmagan obuna o'z
            //    tarifini saqlaydi. Muddati o'tgan yoki bekor qilingani Free:
            //    Faza 0 sxemasida muddat yo'q, xom p.code ko'chirilsa tugagan
            //    sinov muddati muddatsiz pullik tarifga aylanardi.
            migrationBuilder.Sql(
                """
                UPDATE tenants t SET plan =
                    CASE
                        WHEN s.status = 'Active' AND (s.period_end IS NULL OR s.period_end > now())
                            THEN p.code
                        ELSE 'Free'
                    END
                FROM subscriptions s
                JOIN plans p ON p.id = s.plan_id
                WHERE s.tenant_id = t.id;
                """);

            // 3) Default olib tashlanadi — sxema InitialAccessSchema bilan bir xil bo'ladi.
            migrationBuilder.Sql("ALTER TABLE tenants ALTER COLUMN plan DROP DEFAULT;");

            // 4) Jadvallar — bog'liqlik tartibida.
            migrationBuilder.DropTable(
                name: "audit_events");

            migrationBuilder.DropTable(
                name: "subscriptions");

            migrationBuilder.DropTable(
                name: "plans");
        }
    }
}
