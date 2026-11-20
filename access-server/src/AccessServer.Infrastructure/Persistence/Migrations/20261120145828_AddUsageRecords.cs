using System;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace AccessServer.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddUsageRecords : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "usage_records",
                columns: table => new
                {
                    id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    tenant_id = table.Column<int>(type: "integer", nullable: false),
                    tunnel_id = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    window_start = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    window_end = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    bytes_in = table.Column<long>(type: "bigint", nullable: false),
                    bytes_out = table.Column<long>(type: "bigint", nullable: false),
                    connections = table.Column<int>(type: "integer", nullable: false),
                    rejected = table.Column<int>(type: "integer", nullable: false),
                    reported_by = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_usage_records", x => x.id);
                    table.CheckConstraint("ck_usage_records_counters", "bytes_in >= 0 AND bytes_out >= 0 AND connections >= 0 AND rejected >= 0");
                    table.CheckConstraint("ck_usage_records_window", "window_end > window_start");
                    table.ForeignKey(
                        name: "fk_usage_records_tenants_tenant_id",
                        column: x => x.tenant_id,
                        principalTable: "tenants",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "ix_usage_records_tenant_id_window_start",
                table: "usage_records",
                columns: new[] { "tenant_id", "window_start" });

            migrationBuilder.CreateIndex(
                name: "ix_usage_records_tunnel_id_window_start",
                table: "usage_records",
                columns: new[] { "tunnel_id", "window_start" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "usage_records");
        }
    }
}
