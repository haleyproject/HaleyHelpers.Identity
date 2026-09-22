using static Haley.Internal.IdentityFields;
namespace Haley.Internal;
internal static class IdentityOutboxQueries
{
    internal const string INSERT_DATA = $"""
        INSERT INTO `outbox_data`
          (`msg_id`,`event_type`,`schema_version`,`aggregate_type`,`occurred_at`,`payload`)
        VALUES ({MSG_ID},{EVENT_TYPE},1,{AGGREGATE_TYPE},{OCCURRED_AT},{PAYLOAD});
        """;

    internal const string INSERT_MSG = $"""
        INSERT INTO `outbox_msg`
          (`event_uid`,`aggregate_uid`,`available_at`)
        VALUES ({EVENT_UID},{AGGREGATE_UID},{OCCURRED_AT})
        RETURNING `id`;
        """;

}
