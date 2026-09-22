using static Haley.Internal.IdentityFields;
namespace Haley.Internal;
internal static class IdentityUserQueries
{
    internal const string RESTORE_USER =
        $"UPDATE `user_account` SET `status`=2,`modified_at`={AT},`retired_at`=NULL WHERE `id`={ID} AND `status`=4;";


    internal const string MARK_CONTACT_VERIFICATION_PENDING = $"""
        UPDATE `user_account`
           SET `flags`=`flags` | 4,`modified_at`={AT}
         WHERE `id`={USER_ID};
        """;


    internal const string INSERT_PASSWORD_HISTORY = $"""
        INSERT INTO `password_history`
          (`user_id`,`secret_hash`,`algorithm`,`params`,`created_at`)
        VALUES ({USER_ID},{SECRET_HASH},{ALGORITHM},{PARAMS},{CREATED_AT});
        """;


    internal const string DELETE_CREDENTIALS =
        $"DELETE FROM `credential` WHERE `user_id`={USER_ID};";


    internal const string DELETE_USER_SESSIONS =
        $"DELETE FROM `user_session` WHERE `user_id`={USER_ID};";


    internal const string FIND_USER_FOR_PROFILE_UPDATE = $"""
        SELECT `id` AS local_user_id
          FROM `user_account`
         WHERE `uid`={UID} AND `status`<>4
         LIMIT 1 FOR UPDATE;
        """;


    internal const string ACTIVATE_LOCKED_USER =
        $"UPDATE `user_account` SET `status`=2,`modified_at`={AT} WHERE `id`={ID} AND `status`=8;";


    internal const string ANONYMIZE_LOGIN_ATTEMPTS =
        $"UPDATE `login_attempt` SET `user_uid`=NULL WHERE `user_uid`={USER_UID};";


    internal const string FIND_USER = $"""
        SELECT `uid` AS user_uid,`display_name`,`status`,`normalized`,`flags`,`created_at`,`last_auth_at`
          FROM `user_account` WHERE `uid`={UID} LIMIT 1;
        """;


    internal const string FIND_LOCAL_CREDENTIAL = $"""
        SELECT u.`id` AS local_user_id,c.`id` AS local_credential_id,
               u.`uid` AS user_uid,u.`display_name`,u.`status`,u.`flags`,
               u.`normalized`,u.`created_at`,u.`last_auth_at`,
               c.`secret_hash`,c.`algorithm`,c.`params`
          FROM `user_account` u
          JOIN `credential` c ON c.`user_id`=u.`id`
         WHERE u.`normalized`={USERNAME}
           AND c.`kind`='password' AND c.`status`=2 AND c.`retired_at` IS NULL
         ORDER BY c.`id` DESC LIMIT 1;
        """;


    internal const string LIST_USERS = $"""
        SELECT `uid` AS user_uid,`display_name`,`status`,`normalized`,`flags`,`created_at`,`last_auth_at`
          FROM `user_account`
         WHERE ({QUERY} IS NULL OR `display_name` LIKE {QUERY_LIKE} OR `normalized` LIKE {QUERY_LIKE}
                OR LOWER(HEX(`uid`)) LIKE {QUERY_UID_LIKE})
           AND ({STATUS} IS NULL OR `status`={STATUS})
           AND ({AFTER_UID} IS NULL OR `uid`>{AFTER_UID})
         ORDER BY `uid` LIMIT {LIMIT};
        """;


    internal const string LIST_LOGIN_ATTEMPTS = $"""
        SELECT `id`,`user_uid`,`application_uid`,`outcome`,`reason_code`,`occurred_at`
          FROM `login_attempt`
         WHERE `user_uid`={USER_UID}
         ORDER BY `occurred_at` DESC,`id` DESC
         LIMIT {LIMIT} OFFSET {OFFSET};
        """;


    internal const string DELETE_RECOVERY_CODES =
        $"DELETE FROM `recovery_code` WHERE `user_id`={USER_ID};";


    internal const string DELETE_CONTACT_METHODS =
        $"DELETE FROM `contact_method` WHERE `user_id`={USER_ID};";


    internal const string REVOKE_ACTIVE_SESSIONS =
        $"UPDATE `user_session` SET `status`=64,`ended_at`={AT} WHERE `user_id`={USER_ID} AND `status`=2;";


    internal const string INSERT_USER = $"""
        INSERT IGNORE INTO `user_account`
          (`uid`,`status`,`normalized`,`display_name`,`flags`,`created_at`,`modified_at`)
        VALUES ({UID},{STATUS},{USERNAME},{DISPLAY_NAME},{FLAGS},{CREATED_AT},{CREATED_AT})
        RETURNING `id`;
        """;


    internal const string INSERT_ACCOUNT_LOCK =
        $"INSERT INTO `account_lock` (`user_id`,`reason_code`,`locked_at`) VALUES ({USER_ID},{REASON},{AT});";


    internal const string DELETE_SUBJECT_VERIFICATION_CHALLENGES = $"""
        DELETE challenge_record FROM `verification_challenge` challenge_record
          JOIN `challenge_ctx` challenge_context ON challenge_context.`challenge_id`=challenge_record.`id`
         WHERE challenge_context.`subject_uid`={USER_UID};
        """;


    internal const string DELETE_ACCOUNT_LOCKS =
        $"DELETE FROM `account_lock` WHERE `user_id`={USER_ID};";


    internal const string DELETE_MFA_METHODS =
        $"DELETE FROM `mfa_method` WHERE `user_id`={USER_ID};";


    internal const string DELETE_USER_PROFILE =
        $"DELETE FROM `user_profile` WHERE `user_id`={USER_ID};";


    internal const string FIND_CREDENTIAL_FOR_ADMIN_RESET = $"""
        SELECT u.`id` AS local_user_id,c.`id` AS local_credential_id,
               c.`secret_hash`,c.`algorithm`,c.`params`
          FROM `user_account` u
          JOIN `credential` c ON c.`user_id`=u.`id`
         WHERE u.`uid`={UID} AND u.`status`<>4
           AND c.`kind`='password' AND c.`status`=2 AND c.`retired_at` IS NULL
         ORDER BY c.`id` DESC LIMIT 1 FOR UPDATE;
        """;


    internal const string FIND_USER_FOR_LOGIN_EMAIL_CONTACT = $"""
        SELECT `id` AS local_user_id
          FROM `user_account`
         WHERE `uid`={UID} AND `status`<>4
         LIMIT 1 FOR UPDATE;
        """;


    internal const string FIND_CREDENTIAL_FOR_CHANGE = $"""
        SELECT c.`secret_hash`,c.`algorithm`,c.`params`
          FROM `credential` c
         WHERE c.`id`={CREDENTIAL_ID} AND c.`user_id`={USER_ID}
           AND c.`status`=2 AND c.`retired_at` IS NULL
         LIMIT 1 FOR UPDATE;
        """;


    internal const string UPDATE_PROFILE_DISPLAY_NAME = $"""
        UPDATE `user_account`
           SET `display_name`={DISPLAY_NAME},`modified_at`={MODIFIED_AT}
         WHERE `id`={USER_ID};
        """;


    internal const string RETIRE_CREDENTIAL = $"""
        UPDATE `credential`
           SET `status`=4,`retired_at`={AT}
         WHERE `id`={CREDENTIAL_ID} AND `user_id`={USER_ID}
           AND `status`=2 AND `retired_at` IS NULL;
        """;


    internal const string FIND_EMAIL_CONTACT_FOR_OVERRIDE = $"""
        SELECT c.`id` AS local_contact_id,c.`verified_at`,u.`id` AS local_user_id
          FROM `contact_method` c
          JOIN `user_account` u ON u.`id`=c.`user_id`
         WHERE u.`uid`={UID} AND u.`status`<>4
           AND c.`uid`={CONTACT_UID} AND c.`kind`='email' AND c.`retired_at` IS NULL
         LIMIT 1 FOR UPDATE;
        """;


    internal const string FIND_USER_PROFILE = $"""
        SELECT u.`uid` AS user_uid,u.`display_name`,
               p.`given_name`,p.`family_name`,p.`preferred_name`,p.`locale`,
               p.`time_zone`,p.`avatar_uri`,COALESCE(p.`modified_at`,u.`modified_at`) AS modified_at
          FROM `user_account` u
          LEFT JOIN `user_profile` p ON p.`user_id`=u.`id`
         WHERE u.`uid`={UID} LIMIT 1;
        """;


    internal const string DELETE_SUBJECT_VERIFICATION_GRANTS = $"""
        DELETE grant_record
          FROM `verification_grant` grant_record
          JOIN `verification_challenge` challenge_record ON challenge_record.`id`=grant_record.`challenge_id`
          JOIN `challenge_ctx` challenge_context ON challenge_context.`challenge_id`=challenge_record.`id`
         WHERE challenge_context.`subject_uid`={USER_UID};
        """;


    internal const string FIND_STATUS_FOR_UPDATE =
        $"SELECT `id` AS local_user_id,`status` FROM `user_account` WHERE `uid`={UID} LIMIT 1 FOR UPDATE;";


    internal const string RELEASE_ACCOUNT_LOCK =
        $"UPDATE `account_lock` SET `released_at`={AT} WHERE `user_id`={USER_ID} AND `released_at` IS NULL;";


    internal const string INSERT_LOGIN_EMAIL_CONTACT = $"""
        INSERT IGNORE INTO `contact_method`
          (`uid`,`user_id`,`kind`,`normalized`,`display`,`flags`,`created_at`)
        VALUES ({CONTACT_UID},{USER_ID},'email',{EMAIL},{EMAIL},3,{CREATED_AT});
        """;


    internal const string OVERRIDE_EMAIL_VERIFICATION =
        $"UPDATE `contact_method` SET `verified_at`={AT} WHERE `id`={ID} AND `verified_at` IS NULL;";


    internal const string SET_PASSWORD_CHANGE_REQUIRED = $"""
        UPDATE `user_account`
           SET `flags`=CASE WHEN {REQUIRED}=1 THEN `flags` | 2 ELSE `flags` & 4294967293 END,
               `modified_at`={AT}
         WHERE `id`={USER_ID};
        """;


    internal const string DELETE_USER_ACCOUNT =
        $"DELETE FROM `user_account` WHERE `id`={ID} AND `status`=4;";


    internal const string LIST_USER_PAGE = $"""
        SELECT `uid` AS user_uid,`display_name`,`status`,`normalized`,`flags`,`created_at`,`last_auth_at`
          FROM `user_account`
         WHERE ({QUERY} IS NULL OR `display_name` LIKE {QUERY_LIKE} OR `normalized` LIKE {QUERY_LIKE}
                OR LOWER(HEX(`uid`)) LIKE {QUERY_UID_LIKE})
           AND ({STATUS} IS NULL OR `status`={STATUS})
           AND ({ACTIVITY}='all'
                OR ({ACTIVITY}='never_logged_in' AND `last_auth_at` IS NULL)
                OR ({ACTIVITY}='has_logged_in' AND `last_auth_at` IS NOT NULL)
                OR ({ACTIVITY}='password_change_required' AND (`flags` & 2)=2))
         ORDER BY
           CASE WHEN {SORT}='last_login_newest' AND `last_auth_at` IS NULL THEN 1 ELSE 0 END,
           CASE WHEN {SORT}='last_login_newest' THEN `last_auth_at` END DESC,
           CASE WHEN {SORT}='last_login_oldest' AND `last_auth_at` IS NULL THEN 1 ELSE 0 END,
           CASE WHEN {SORT}='last_login_oldest' THEN `last_auth_at` END ASC,
           CASE WHEN {SORT}='created_oldest' THEN `created_at` END ASC,
           CASE WHEN {SORT}='created_newest' THEN `created_at` END DESC,
           `uid` DESC
         LIMIT {LIMIT} OFFSET {OFFSET};
        """;


    internal const string CLEAR_CONTACT_VERIFICATION_PENDING = $"""
        UPDATE `user_account` u
           SET `flags`=u.`flags` & 4294967291,`modified_at`={AT}
         WHERE u.`id`={USER_ID}
           AND NOT EXISTS (
             SELECT 1 FROM `contact_method` c
              WHERE c.`user_id`=u.`id` AND c.`kind`='email'
                AND c.`retired_at` IS NULL AND c.`verified_at` IS NULL
           );
        """;


    internal const string DELETE_SUBJECT_CHALLENGE_ATTEMPTS = $"""
        DELETE attempt_record
          FROM `challenge_attempt` attempt_record
          JOIN `verification_challenge` challenge_record ON challenge_record.`id`=attempt_record.`challenge_id`
          JOIN `challenge_ctx` challenge_context ON challenge_context.`challenge_id`=challenge_record.`id`
         WHERE challenge_context.`subject_uid`={USER_UID};
        """;


    internal const string ANONYMIZE_VERIFICATION_CONSUMER =
        $"UPDATE `verification_grant` SET `consumer_uid`=NULL WHERE `consumer_uid`={USER_UID};";


    internal const string FIND_ACTIVE_USER_EMAIL_CONTACT = $"""
        SELECT `normalized`
          FROM `contact_method`
         WHERE `user_id`={USER_ID} AND `kind`='email' AND `retired_at` IS NULL
         LIMIT 1 FOR UPDATE;
        """;


    internal const string UPSERT_USER_PROFILE = $"""
        INSERT INTO `user_profile`
          (`user_id`,`given_name`,`family_name`,`preferred_name`,`locale`,`time_zone`,`avatar_uri`,`modified_at`)
        VALUES
          ({USER_ID},{GIVEN_NAME},{FAMILY_NAME},{PREFERRED_NAME},{LOCALE},{TIME_ZONE},{AVATAR_URI},{MODIFIED_AT})
        ON DUPLICATE KEY UPDATE
          `given_name`=VALUES(`given_name`),
          `family_name`=VALUES(`family_name`),
          `preferred_name`=VALUES(`preferred_name`),
          `locale`=VALUES(`locale`),
          `time_zone`=VALUES(`time_zone`),
          `avatar_uri`=VALUES(`avatar_uri`),
          `modified_at`=VALUES(`modified_at`);
        """;


    internal const string UPDATE_STATUS =
        $"UPDATE `user_account` SET `status`={STATUS},`modified_at`={AT},`retired_at`=CASE WHEN {STATUS}=4 THEN {AT} ELSE `retired_at` END WHERE `id`={ID};";


    internal const string INSERT_CREDENTIAL = $"""
        INSERT INTO `credential`
          (`uid`,`user_id`,`kind`,`secret_hash`,`algorithm`,`params`,`status`,`created_at`)
        VALUES ({CREDENTIAL_UID},{USER_ID},'password',{SECRET_HASH},{ALGORITHM},{PARAMS},2,{CREATED_AT});
        """;


    internal const string REVOKE_SESSIONS_AFTER_PASSWORD_CHANGE = $"""
        UPDATE `user_session`
           SET `status`=64,`ended_at`={AT}
         WHERE `user_id`={USER_ID} AND `status`=2;
        """;


    internal const string DELETE_PASSWORD_HISTORY =
        $"DELETE FROM `password_history` WHERE `user_id`={USER_ID};";

}
