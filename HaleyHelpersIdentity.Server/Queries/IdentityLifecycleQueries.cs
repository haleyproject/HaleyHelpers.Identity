using static Haley.Internal.IdentityFields;
namespace Haley.Internal;
internal static class IdentityLifecycleQueries
{
    internal const string FIND_PASSWORDLESS_SUBJECT_BY_USER = $"""
        SELECT u.`id` AS local_user_id,u.`uid` AS user_uid,u.`display_name`,u.`status`,
               u.`normalized`,u.`flags`,u.`created_at`,u.`last_auth_at`,
               c.`normalized` AS destination_normalized,c.`display` AS destination_display
          FROM `user_account` u
          JOIN `contact_method` c ON c.`user_id`=u.`id`
         WHERE u.`uid`={USER_UID} AND c.`kind`='email'
           AND c.`verified_at` IS NOT NULL AND c.`retired_at` IS NULL
           AND (c.`flags` & 2)=2
         ORDER BY c.`id` LIMIT 1;
        """;


    internal const string INSERT_ENROLLED_PASSWORD = $"""
        INSERT INTO `credential` (`uid`,`user_id`,`kind`,`secret_hash`,`algorithm`,`params`,`status`,`created_at`)
        VALUES ({CREDENTIAL_UID},{USER_ID},'password',{SECRET_HASH},{ALGORITHM},{PARAMS},2,{OCCURRED_AT});
        """;


    internal const string FIND_PENDING_EMAIL = $"""
        SELECT u.`uid` AS user_uid,u.`display_name`,u.`status`,u.`normalized`,u.`flags`,u.`created_at`,u.`last_auth_at`
          FROM `contact_method` c JOIN `user_account` u ON u.`id`=c.`user_id`
         WHERE c.`kind`='email' AND c.`normalized`={EMAIL} AND c.`verified_at` IS NULL
           AND c.`retired_at` IS NULL AND u.`status` IN (1,2) LIMIT 1;
        """;


    internal const string INSERT_CHALLENGE_ATTEMPT = $"""
        INSERT INTO `challenge_attempt` (`challenge_id`,`outcome`,`ip_hash`,`user_agent_hash`,`occurred_at`)
        VALUES ({CHALLENGE_ID},{OUTCOME},{IP_HASH},{USER_AGENT_HASH},{OCCURRED_AT});
        """;


    internal const string VERIFY_USER_EMAIL = $"""
        UPDATE `contact_method` SET `verified_at`=COALESCE(`verified_at`,{OCCURRED_AT})
         WHERE `user_id`={USER_ID} AND `kind`='email' AND `retired_at` IS NULL;
        """;


    internal const string RETIRE_CURRENT_PASSWORDS = $"""
        UPDATE `credential` SET `status`=4,`retired_at`={OCCURRED_AT}
         WHERE `user_id`={USER_ID} AND `kind`='password' AND `status`=2;
        """;


    internal const string INSERT_CHALLENGE = $"""
        INSERT INTO `verification_challenge`
          (`uid`,`policy_id`,`status`,`attempts`,`created_at`,`not_before`,`expires_at`)
        VALUES ({UID},{ID},1,0,{CREATED_AT},{NOT_BEFORE},{EXPIRES_AT})
        RETURNING `id`;
        """;


    internal const string CHALLENGE_THROTTLED = $"""
        SELECT COUNT(*) FROM `verification_challenge` c
        JOIN `verification_policy` p ON p.`id`=c.`policy_id`
        JOIN `challenge_ctx` ctx ON ctx.`challenge_id`=c.`id`
        WHERE ctx.`application_uid`={APPLICATION_UID} AND ctx.`purpose`={REASON} AND ctx.`subject_uid`={USER_UID}
          AND ((c.`status`=1 AND DATE_ADD(c.`created_at`, INTERVAL p.`resend_delay` SECOND)>{CREATED_AT})
            OR (c.`status`=8192 AND DATE_ADD(c.`created_at`, INTERVAL {COOLDOWN_SEC} SECOND)>{CREATED_AT}));
        """;


    internal const string CONSUME_GRANT = $"""
        UPDATE `verification_grant` SET `consumed_at`={OCCURRED_AT},`consumer_uid`={USER_UID}
         WHERE `id`={ID} AND `consumed_at` IS NULL;
        """;


    internal const string INSERT_EMAIL_CONTACT = $"""
        INSERT INTO `contact_method`
          (`uid`,`user_id`,`kind`,`normalized`,`display`,`flags`,`created_at`)
        VALUES ({CONTACT_UID},{USER_ID},'email',{EMAIL},{DISPLAY_NAME},3,{CREATED_AT});
        """;


    internal const string FIND_PASSWORD_RESET_GRANT_CREDENTIAL = $"""
        SELECT credential_record.`uid` AS credential_uid,credential_record.`secret_hash`,
               credential_record.`algorithm`,credential_record.`params`
          FROM `verification_grant` g
          JOIN `grant_ctx` ctx ON ctx.`grant_id`=g.`id`
          JOIN `user_account` u ON u.`uid`=ctx.`subject_uid`
          JOIN `credential` credential_record ON credential_record.`user_id`=u.`id`
             AND credential_record.`kind`='password' AND credential_record.`status`=2
             AND credential_record.`retired_at` IS NULL
         WHERE g.`uid`={GRANT_UID} AND ctx.`application_uid`={APPLICATION_UID}
           AND ctx.`purpose`='identity.password.reset' AND g.`consumed_at` IS NULL
           AND g.`expires_at`>{OCCURRED_AT} AND u.`status`=2
         ORDER BY credential_record.`id` DESC LIMIT 1;
        """;


    internal const string CANCEL_PENDING_CHALLENGES = $"""
        UPDATE `verification_challenge` c
        JOIN `challenge_ctx` ctx ON ctx.`challenge_id`=c.`id`
           SET c.`status`=4096,c.`consumed_at`={CREATED_AT}
         WHERE ctx.`application_uid`={APPLICATION_UID} AND ctx.`purpose`={REASON} AND ctx.`subject_uid`={USER_UID}
           AND c.`status`=1;
        """;


    internal const string LOCK_PASSWORD_RESET_GRANT = $"""
        SELECT g.`id` AS local_grant_id,c.`id` AS local_challenge_id,u.`id` AS local_user_id,
               credential_record.`id` AS local_credential_id,credential_record.`uid` AS credential_uid,credential_record.`secret_hash`,
               credential_record.`algorithm`,credential_record.`params`,ctx.`purpose`,ctx.`context_hash`,
               g.`expires_at`,g.`consumed_at`,u.`uid` AS user_uid,u.`status`,2 AS client_status
          FROM `verification_grant` g
          JOIN `grant_ctx` ctx ON ctx.`grant_id`=g.`id`
          JOIN `verification_challenge` c ON c.`id`=g.`challenge_id`
          JOIN `user_account` u ON u.`uid`=ctx.`subject_uid`
          JOIN `credential` credential_record ON credential_record.`user_id`=u.`id`
             AND credential_record.`kind`='password' AND credential_record.`status`=2
             AND credential_record.`retired_at` IS NULL
         WHERE g.`uid`={GRANT_UID} AND ctx.`application_uid`={APPLICATION_UID}
         ORDER BY credential_record.`id` DESC LIMIT 1 FOR UPDATE;
        """;


    internal const string LIST_VERIFIED_EMAILS = $"""
        SELECT c.`normalized`
          FROM `contact_method` c
          JOIN `user_account` u ON u.`id`=c.`user_id`
         WHERE u.`uid`={USER_UID} AND c.`kind`='email'
           AND c.`verified_at` IS NOT NULL AND c.`retired_at` IS NULL;
        """;


    internal const string FAIL_CHALLENGE = $"""
        UPDATE `verification_challenge` SET `attempts`=`attempts`+1,
          `status`=CASE WHEN {EXHAUSTED}=1 THEN 8192 ELSE `status` END
         WHERE `id`={CHALLENGE_ID} AND `status`=1;
        """;


    internal const string LOCK_ENROLLMENT_GRANT = $"""
        SELECT g.`id` AS local_grant_id,c.`id` AS local_challenge_id,u.`id` AS local_user_id,
               ctx.`purpose`,ctx.`context_hash`,g.`expires_at`,g.`consumed_at`,u.`status`,
               2 AS client_status
          FROM `verification_grant` g
          JOIN `grant_ctx` ctx ON ctx.`grant_id`=g.`id`
          JOIN `verification_challenge` c ON c.`id`=g.`challenge_id`
          JOIN `user_account` u ON u.`uid`=ctx.`subject_uid`
         WHERE g.`uid`={GRANT_UID} AND ctx.`application_uid`={APPLICATION_UID} AND ctx.`subject_uid`={USER_UID}
         LIMIT 1 FOR UPDATE;
        """;


    internal const string FIND_USER_BY_ORIGIN = $"""
        SELECT u.`uid` AS user_uid,u.`display_name`,u.`status`,u.`normalized`,u.`flags`,u.`created_at`,u.`last_auth_at`
          FROM `user_origin` o JOIN `user_account` u ON u.`id`=o.`user_id`
         WHERE o.`application_uid`={APPLICATION_UID} AND o.`origin`={ORIGIN} AND o.`source_hash`={SOURCE_HASH}
           AND u.`status`<>4 LIMIT 1;
        """;


    internal const string INSERT_CHALLENGE_CTX = $"""
        INSERT INTO `challenge_ctx`
          (`challenge_id`,`tenant_uid`,`application_uid`,`purpose`,`subject_type`,`subject_uid`,`destination_hash`,`context_hash`)
        VALUES ({CHALLENGE_ID},{OWNER_TENANT_UID},{APPLICATION_UID},{REASON},'user',{USER_UID},{DESTINATION_HASH},{CONTEXT_HASH});
        """;


    internal const string INSERT_USER_ORIGIN = $"""
        INSERT IGNORE INTO `user_origin` (`user_id`,`application_uid`,`origin`,`source_hash`,`created_at`)
        SELECT u.`id`,{APPLICATION_UID},{ORIGIN},{SOURCE_HASH},{CREATED_AT}
          FROM `user_account` u WHERE u.`uid`={USER_UID};
        """;


    internal const string FIND_CHALLENGE = $"""
        SELECT c.`id` AS local_challenge_id,c.`uid` AS challenge_uid,ctx.`application_uid`,ctx.`subject_uid`,
               ctx.`purpose`,ctx.`context_hash`,c.`status`,c.`attempts`,c.`not_before`,c.`expires_at`,
               p.`max_attempts`,p.`grant_validity`,d.`code_hash`,d.`code_algorithm`,d.`code_params`,d.`code_expires_at`,d.`link_hash`
          FROM `verification_challenge` c
          JOIN `verification_policy` p ON p.`id`=c.`policy_id`
          JOIN `challenge_ctx` ctx ON ctx.`challenge_id`=c.`id`
          JOIN `challenge_data` d ON d.`challenge_id`=c.`id`
         WHERE c.`uid`={UID} LIMIT 1;
        """;


    internal const string INSERT_MAILBOX_USER = $"""
        INSERT IGNORE INTO `user_account`
          (`uid`,`status`,`normalized`,`display_name`,`flags`,`created_at`,`modified_at`)
        VALUES ({UID},{STATUS},{USERNAME},{DISPLAY_NAME},{FLAGS},{CREATED_AT},{CREATED_AT}) RETURNING `id`;
        """;


    internal const string FIND_VERIFIED_EMAIL = $"""
        SELECT u.`uid` AS user_uid,u.`display_name`,u.`status`,u.`normalized`,u.`flags`,u.`created_at`,u.`last_auth_at`
          FROM `contact_method` c JOIN `user_account` u ON u.`id`=c.`user_id`
         WHERE c.`kind`='email' AND c.`normalized`={EMAIL} AND c.`verified_at` IS NOT NULL
           AND c.`retired_at` IS NULL AND u.`status`<>4 LIMIT 1;
        """;


    internal const string ACTIVATE_ENROLLED_USER = $"""
        UPDATE `user_account` SET `status`=2,`flags`=(`flags` & 4294967289),`modified_at`={OCCURRED_AT}
         WHERE `id`={USER_ID};
        """;


    internal const string INSERT_CHALLENGE_DATA = $"""
        INSERT INTO `challenge_data`
          (`challenge_id`,`code_hash`,`code_algorithm`,`code_params`,`code_expires_at`,`link_hash`)
        VALUES ({CHALLENGE_ID},{CODE_HASH},{CODE_ALGORITHM},{CODE_PARAMS},{CODE_EXPIRES_AT},{LINK_HASH});
        """;


    internal const string LOCK_CHALLENGE = $"""
        SELECT c.`status`,c.`attempts`,c.`not_before`,c.`expires_at`,p.`max_attempts`
          FROM `verification_challenge` c
          JOIN `verification_policy` p ON p.`id`=c.`policy_id`
         WHERE c.`id`={CHALLENGE_ID} LIMIT 1 FOR UPDATE;
        """;


    internal const string CONSUME_CHALLENGE = $"""
        UPDATE `verification_challenge` SET `status`=2048,`consumed_at`={OCCURRED_AT}
         WHERE `id`={CHALLENGE_ID} AND `status`=1024;
        """;

    internal const string FIND_PASSWORDLESS_SUBJECT_BY_EMAIL = $"""
        SELECT u.`id` AS local_user_id,u.`uid` AS user_uid,u.`display_name`,u.`status`,
               u.`normalized`,u.`flags`,u.`created_at`,u.`last_auth_at`,
               c.`normalized` AS destination_normalized,c.`display` AS destination_display
          FROM `contact_method` c
          JOIN `user_account` u ON u.`id`=c.`user_id`
         WHERE c.`kind`='email' AND c.`normalized`={DESTINATION}
           AND c.`verified_at` IS NOT NULL AND c.`retired_at` IS NULL
           AND (c.`flags` & 2)=2
         LIMIT 1;
        """;


    internal const string VERIFY_CHALLENGE = $"""
        UPDATE `verification_challenge` SET `status`=1024,`attempts`=`attempts`+1,`verified_at`={OCCURRED_AT}
         WHERE `id`={CHALLENGE_ID} AND `status`=1;
        """;


    internal const string INSERT_GRANT = $"""
        INSERT INTO `verification_grant`
          (`uid`,`challenge_id`,`issued_at`,`expires_at`)
        SELECT {GRANT_UID},c.`id`,{OCCURRED_AT},{GRANT_EXPIRES_AT}
          FROM `verification_challenge` c WHERE c.`id`={CHALLENGE_ID};
        """;


    internal const string FIND_POLICY_ID = $"""
        SELECT `id` FROM `verification_policy`
         WHERE `code`={POLICY_CODE} AND (`flags` & 1)=1 LIMIT 1;
        """;


    internal const string INSERT_GRANT_CTX = $"""
        INSERT INTO `grant_ctx`
          (`grant_id`,`tenant_uid`,`application_uid`,`purpose`,`subject_type`,`subject_uid`,`context_hash`)
        SELECT g.`id`,ctx.`tenant_uid`,ctx.`application_uid`,ctx.`purpose`,ctx.`subject_type`,ctx.`subject_uid`,ctx.`context_hash`
          FROM `verification_grant` g
          JOIN `challenge_ctx` ctx ON ctx.`challenge_id`=g.`challenge_id`
         WHERE g.`uid`={GRANT_UID};
        """;


    internal const string FIND_PASSWORD_RESET_SUBJECT = $"""
        SELECT u.`uid` AS user_uid,u.`status`,c.`normalized` AS destination_normalized,
               c.`display` AS destination_display
          FROM `contact_method` c
          JOIN `user_account` u ON u.`id`=c.`user_id`
         WHERE c.`kind`={KIND} AND c.`normalized`={DESTINATION}
           AND c.`verified_at` IS NOT NULL AND c.`retired_at` IS NULL
           AND (c.`flags` & 2)=2 AND u.`status`=2
           AND EXISTS (
               SELECT 1 FROM `credential` credential_record
                WHERE credential_record.`user_id`=u.`id`
                  AND credential_record.`kind`='password'
                  AND credential_record.`status`=2
                  AND credential_record.`retired_at` IS NULL)
         LIMIT 1;
        """;

}
