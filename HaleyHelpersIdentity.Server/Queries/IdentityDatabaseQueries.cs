namespace Haley.Internal;

internal static class IdentityDatabaseQueries
{
    internal static string Install(string schema, string seed, string schemaHash, string seedHash) => $"""
        {schema}
        {seed}
        INSERT IGNORE INTO `__schema_history` (`script_name`,`checksum`,`applied_by`)
        VALUES ('haley.identity.schema:{schemaHash}','{schemaHash}','Haley.Identity');
        INSERT IGNORE INTO `__schema_history` (`script_name`,`checksum`,`applied_by`)
        VALUES ('haley.identity.seed:{seedHash}','{seedHash}','Haley.Identity');
        """;

    internal const string CheckSessionShape = """
        SELECT COUNT(*) FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='user_session' AND COLUMN_NAME IN ('application_uid','kind');
        """;
}
