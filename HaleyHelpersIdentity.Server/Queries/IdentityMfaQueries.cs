using static Haley.Internal.IdentityFields;
namespace Haley.Internal;
internal static class IdentityMfaQueries
{
    internal const string TOUCH_METHOD = $"""
        UPDATE `mfa_method` SET `last_used_at`={MODIFIED_AT}
         WHERE `uid`={METHOD_UID} AND `status`=2
           AND (`last_used_at` IS NULL OR `last_used_at`<{MODIFIED_AT});
        """;

    internal const string RESOLVE_REPLACEMENT = $"""
        SELECT replacement.`id`
          FROM `mfa_method` replacement
          JOIN `user_account` u ON u.`id`=replacement.`user_id`
         WHERE replacement.`uid`={REPLACE_UID} AND u.`uid`={USER_UID}
           AND replacement.`kind`='totp' AND replacement.`status`=2
         LIMIT 1 FOR UPDATE;
        """;

    internal const string INSERT_METHOD = $"""
        INSERT INTO `mfa_method` (`uid`,`user_id`,`kind`,`label`,`status`,`created_at`)
        SELECT {METHOD_UID},u.`id`,{KIND},{LABEL},1,{CREATED_AT} FROM `user_account` u
         WHERE u.`uid`={USER_UID} AND u.`status`<>4 RETURNING `id`;
        """;

    internal const string FIND_ENROLLMENT = $"""
        SELECT m.`id` AS local_method_id,m.`uid` AS method_uid,u.`uid` AS user_uid,m.`kind`,m.`label`,m.`status`,
               m.`created_at`,m.`verified_at`,m.`last_used_at`,d.`secret_enc`,d.`public_data`,
               e.`attempts`,e.`max_attempts`,e.`expires_at`,e.`consumed_at`,e.`return_uri`,
               replacement.`uid` AS replace_uid
          FROM `mfa_enroll` e
          JOIN `mfa_method` m ON m.`id`=e.`method_id`
          JOIN `user_account` u ON u.`id`=m.`user_id`
          JOIN `mfa_data` d ON d.`method_id`=m.`id`
          LEFT JOIN `mfa_method` replacement ON replacement.`id`=e.`replace_id`
         WHERE e.`token_hash`={TOKEN_HASH} LIMIT 1;
        """;

    internal const string RETIRE_PENDING_METHODS = $"""
        UPDATE `mfa_method` m
          JOIN `user_account` u ON u.`id`=m.`user_id`
           SET m.`status`=4
         WHERE u.`uid`={USER_UID} AND m.`kind`='totp' AND m.`status`=1;
        """;

    internal const string FIND_METHOD = $"""
        SELECT m.`id` AS local_method_id,m.`uid` AS method_uid,u.`uid` AS user_uid,m.`kind`,m.`label`,m.`status`,
               m.`created_at`,m.`verified_at`,m.`last_used_at`,d.`secret_enc`,d.`public_data`
          FROM `mfa_method` m JOIN `user_account` u ON u.`id`=m.`user_id`
          LEFT JOIN `mfa_data` d ON d.`method_id`=m.`id` WHERE m.`uid`={METHOD_UID} LIMIT 1;
        """;

    internal const string DELETE_RECOVERY = $"DELETE FROM `recovery_code` WHERE `user_id`={USER_ID};";

    internal const string RETIRE_METHOD_BY_ID = $"""
        UPDATE `mfa_method` SET `status`=4
         WHERE `id`={METHOD_ID} AND `status`=2;
        """;

    internal const string FAIL_ENROLLMENT = $"""
        UPDATE `mfa_enroll`
           SET `attempts`=`attempts`+1,
               `consumed_at`=CASE WHEN `attempts`+1>=`max_attempts` THEN {MODIFIED_AT} ELSE `consumed_at` END
         WHERE `token_hash`={TOKEN_HASH} AND `consumed_at` IS NULL AND `expires_at`>{MODIFIED_AT};
        """;

    internal const string RETIRE_METHOD = $"""
        UPDATE `mfa_method` m
          JOIN `user_account` u ON u.`id`=m.`user_id`
           SET m.`status`=4
         WHERE u.`uid`={USER_UID} AND m.`uid`={METHOD_UID}
           AND m.`kind`='totp' AND m.`status` IN (2,1);
        """;

    internal const string CONSUME_METHOD_ENROLLMENT = $"""
        UPDATE `mfa_enroll` e
          JOIN `mfa_method` m ON m.`id`=e.`method_id`
          JOIN `user_account` u ON u.`id`=m.`user_id`
           SET e.`consumed_at`=COALESCE(e.`consumed_at`,{MODIFIED_AT})
         WHERE u.`uid`={USER_UID} AND m.`uid`={METHOD_UID};
        """;

    internal const string RESOLVE_USER = $"SELECT `id` FROM `user_account` WHERE `uid`={USER_UID} AND `status`<>4 LIMIT 1;";

    internal const string LIST = $"""
        SELECT m.`uid` AS method_uid,u.`uid` AS user_uid,m.`kind`,m.`label`,m.`status`,m.`created_at`,m.`verified_at`,m.`last_used_at`
          FROM `mfa_method` m JOIN `user_account` u ON u.`id`=m.`user_id`
         WHERE u.`uid`={USER_UID} ORDER BY m.`created_at`;
        """;

    internal const string CONSUME_RECOVERY = $"""
        UPDATE `recovery_code` r JOIN `user_account` u ON u.`id`=r.`user_id`
           SET r.`used_at`={MODIFIED_AT}
         WHERE u.`uid`={USER_UID} AND r.`code_hash`={CODE_HASH} AND r.`used_at` IS NULL;
        """;

    internal const string CONSUME_ENROLLMENT = $"""
        UPDATE `mfa_enroll` SET `consumed_at`={MODIFIED_AT}
         WHERE `token_hash`={TOKEN_HASH} AND `consumed_at` IS NULL;
        """;

    internal const string INSERT_RECOVERY = $"""
        INSERT INTO `recovery_code` (`user_id`,`code_hash`,`created_at`) VALUES ({USER_ID},{CODE_HASH},{CREATED_AT});
        """;

    internal const string LOCK_ENROLLMENT = $"""
        SELECT e.`method_id`,e.`replace_id`,e.`attempts`,e.`max_attempts`,e.`expires_at`,e.`consumed_at`
          FROM `mfa_enroll` e WHERE e.`token_hash`={TOKEN_HASH} LIMIT 1 FOR UPDATE;
        """;

    internal const string INSERT_ENROLLMENT = $"""
        INSERT INTO `mfa_enroll`
          (`method_id`,`token_hash`,`application_uid`,`return_uri`,`replace_id`,`attempts`,`max_attempts`,`expires_at`)
        VALUES ({METHOD_ID},{TOKEN_HASH},{APPLICATION_UID},{RETURN_URI},{ID},0,{MAX_ATTEMPTS},{EXPIRES_AT});
        """;

    internal const string CONFIRM_METHOD = $"""
        UPDATE `mfa_method` SET `status`=2,`verified_at`={MODIFIED_AT},`last_used_at`={MODIFIED_AT}
         WHERE `uid`={METHOD_UID} AND `status`=1;
        """;

    internal const string CONSUME_PENDING_ENROLLMENTS = $"""
        UPDATE `mfa_enroll` e
          JOIN `mfa_method` m ON m.`id`=e.`method_id`
          JOIN `user_account` u ON u.`id`=m.`user_id`
           SET e.`consumed_at`=COALESCE(e.`consumed_at`,{MODIFIED_AT})
         WHERE u.`uid`={USER_UID} AND m.`kind`='totp' AND m.`status`=1;
        """;

    internal const string INSERT_DATA = $"""
        INSERT INTO `mfa_data` (`method_id`,`secret_enc`,`public_data`) VALUES ({METHOD_ID},{SECRET_ENC},{PUBLIC_DATA});
        """;

    internal const string ACTIVATE_METHOD_BY_ID = $"""
        UPDATE `mfa_method` SET `status`=2,`verified_at`={MODIFIED_AT},`last_used_at`={MODIFIED_AT}
         WHERE `id`={METHOD_ID} AND `status`=1;
        """;
}
