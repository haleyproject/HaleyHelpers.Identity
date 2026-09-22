using static Haley.Internal.IdentityFields;
namespace Haley.Internal;
internal static class IdentitySessionQueries
{
    internal const string RELEASE_EXPIRED_ACCOUNT_LOCKS = $"""
        UPDATE `account_lock`
           SET `released_at`={AT}
         WHERE `user_id`={USER_ID} AND `released_at` IS NULL
           AND `expires_at` IS NOT NULL AND `expires_at`<={AT};
        """;


    internal const string COUNT_ACTIVE_ACCOUNT_LOCKS = $"""
        SELECT COUNT(*) FROM `account_lock`
         WHERE `user_id`={USER_ID} AND `released_at` IS NULL
           AND (`expires_at` IS NULL OR `expires_at`>{AT});
        """;


    internal const string COUNT_FAILED_ATTEMPTS_SINCE_BOUNDARY = $"""
        SELECT COUNT(*)
          FROM `login_attempt`
         WHERE `user_uid`={USER_UID} AND `outcome`='invalid_credential'
           AND `occurred_at` > GREATEST(
                 COALESCE((SELECT MAX(success_record.`occurred_at`)
                             FROM `login_attempt` success_record
                            WHERE success_record.`user_uid`={USER_UID}
                              AND success_record.`outcome`='success'),'1000-01-01'),
                 COALESCE((SELECT MAX(lock_record.`locked_at`)
                             FROM `account_lock` lock_record
                            WHERE lock_record.`user_id`={USER_ID}),'1000-01-01'));
        """;


    internal const string INSERT_LOGIN_ATTEMPT = $"""
        INSERT INTO `login_attempt`
          (`user_uid`,`hint_hash`,`application_uid`,`outcome`,`reason_code`,`ip_hash`,`user_agent_hash`,`occurred_at`)
        VALUES ({USER_UID},{HINT_HASH},{APPLICATION_UID},{OUTCOME},{REASON_CODE},{IP_HASH},{USER_AGENT_HASH},{OCCURRED_AT});
        """;


    internal const string INSERT_AUTOMATIC_ACCOUNT_LOCK = $"""
        INSERT INTO `account_lock`
          (`user_id`,`reason_code`,`locked_at`,`expires_at`)
        VALUES ({USER_ID},'failed_login_threshold',{AT},{EXPIRES_AT});
        """;

}
