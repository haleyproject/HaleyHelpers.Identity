using static Haley.Internal.IdentityFields;

namespace Haley.Internal;

internal static class IdentityFederationQueries
{
    internal const string FIND_PROVIDER = $"""
        SELECT p.`id` AS local_provider_id,p.`uid` AS provider_uid,p.`code`,p.`protocol`,p.`issuer`,
               p.`status`,p.`modified_at`,i.`config`,COALESCE(JSON_UNQUOTE(JSON_EXTRACT(i.`config`,'$.displayName')),p.`code`) AS display_name
          FROM `identity_provider` p JOIN `identity_provider_info` i ON i.`provider_id`=p.`id`
         WHERE p.`code`={CODE} LIMIT 1;
        """;
    internal const string FIND_PROVIDER_BY_UID = $"""
        SELECT p.`id` AS local_provider_id,p.`uid` AS provider_uid,p.`code`,p.`protocol`,p.`issuer`,
               p.`status`,p.`modified_at`,i.`config`,COALESCE(JSON_UNQUOTE(JSON_EXTRACT(i.`config`,'$.displayName')),p.`code`) AS display_name
          FROM `identity_provider` p JOIN `identity_provider_info` i ON i.`provider_id`=p.`id`
         WHERE p.`uid`={PROVIDER_UID} LIMIT 1;
        """;
    internal const string LIST_PROVIDERS = """
        SELECT p.`id` AS local_provider_id,p.`uid` AS provider_uid,p.`code`,p.`protocol`,p.`issuer`,
               p.`status`,p.`modified_at`,i.`config`,COALESCE(JSON_UNQUOTE(JSON_EXTRACT(i.`config`,'$.displayName')),p.`code`) AS display_name
          FROM `identity_provider` p JOIN `identity_provider_info` i ON i.`provider_id`=p.`id`
         ORDER BY p.`code`;
        """;
    internal const string LIST_PROVIDER_DOMAINS = $"""
        SELECT `domain`,`flags` FROM `provider_domain` WHERE `provider_id`={PROVIDER_ID} ORDER BY `domain`;
        """;
    internal const string INSERT_PROVIDER = $"""
        INSERT INTO `identity_provider` (`uid`,`code`,`protocol`,`issuer`,`status`,`created_at`,`modified_at`)
        VALUES ({PROVIDER_UID},{CODE},{PROTOCOL},{ISSUER},{STATUS},{CREATED_AT},{CREATED_AT})
        RETURNING `id`;
        """;
    internal const string UPDATE_PROVIDER = $"""
        UPDATE `identity_provider` SET `code`={CODE},`protocol`={PROTOCOL},
          `issuer`={ISSUER},`status`={STATUS},`modified_at`={MODIFIED_AT} WHERE `id`={PROVIDER_ID};
        """;
    internal const string UPSERT_PROVIDER_INFO = $"""
        INSERT INTO `identity_provider_info` (`provider_id`,`config`) VALUES ({PROVIDER_ID},{CONFIG})
        ON DUPLICATE KEY UPDATE `config`=VALUES(`config`);
        """;
    internal const string DELETE_PROVIDER_DOMAINS = $"DELETE FROM `provider_domain` WHERE `provider_id`={PROVIDER_ID};";
    internal const string INSERT_PROVIDER_DOMAIN = $"""
        INSERT INTO `provider_domain` (`provider_id`,`domain`,`flags`,`created_at`)
        VALUES ({PROVIDER_ID},{DOMAIN},{FLAGS},{CREATED_AT});
        """;

    internal const string FIND_EXTERNAL_IDENTITY = $"""
        SELECT u.`id` AS local_user_id,u.`uid` AS user_uid,u.`display_name`,u.`status`,u.`normalized`,u.`flags`,u.`created_at`,u.`last_auth_at`
          FROM `external_identity` e JOIN `user_account` u ON u.`id`=e.`user_id`
          JOIN `identity_provider` p ON p.`id`=e.`provider_id`
         WHERE p.`uid`={PROVIDER_UID} AND e.`subject`={SUBJECT} LIMIT 1;
        """;
    internal const string FIND_USER_BY_EMAIL = $"""
        SELECT u.`id` AS local_user_id,u.`uid` AS user_uid,u.`display_name`,u.`status`,u.`normalized`,u.`flags`,u.`created_at`,u.`last_auth_at`
          FROM `contact_method` c JOIN `user_account` u ON u.`id`=c.`user_id`
         WHERE c.`kind`='email' AND c.`normalized`={EMAIL} AND c.`verified_at` IS NOT NULL
           AND c.`retired_at` IS NULL LIMIT 1;
        """;
    internal const string INSERT_EXTERNAL_USER = $"""
        INSERT IGNORE INTO `user_account` (`uid`,`status`,`normalized`,`display_name`,`flags`,`created_at`,`modified_at`,`last_auth_at`)
        VALUES ({UID},2,{USERNAME},{DISPLAY_NAME},9,{CREATED_AT},{CREATED_AT},{CREATED_AT}) RETURNING `id`;
        """;
    internal const string INSERT_EXTERNAL_EMAIL = $"""
        INSERT IGNORE INTO `contact_method` (`uid`,`user_id`,`kind`,`normalized`,`display`,`flags`,`verified_at`,`created_at`)
        VALUES ({CONTACT_UID},{USER_ID},'email',{EMAIL},{DISPLAY_NAME},3,{VERIFIED_AT},{CREATED_AT});
        """;
    internal const string INSERT_EXTERNAL_IDENTITY = $"""
        INSERT IGNORE INTO `external_identity` (`user_id`,`provider_id`,`subject`,`linked_at`,`last_auth_at`)
        SELECT {USER_ID},p.`id`,{SUBJECT},{CREATED_AT},{CREATED_AT} FROM `identity_provider` p WHERE p.`uid`={PROVIDER_UID}
        RETURNING `id`;
        """;
    internal const string INSERT_EXTERNAL_INFO = $"""
        INSERT INTO `external_identity_info` (`identity_id`,`claims`) VALUES ({ID},{CLAIMS})
        ON DUPLICATE KEY UPDATE `claims`=VALUES(`claims`);
        """;
    internal const string TOUCH_EXTERNAL_IDENTITY = $"""
        UPDATE `external_identity` e JOIN `identity_provider` p ON p.`id`=e.`provider_id`
           SET e.`last_auth_at`={CREATED_AT}
         WHERE p.`uid`={PROVIDER_UID} AND e.`subject`={SUBJECT};
        """;
    internal const string TOUCH_EXTERNAL_USER = $"""
        UPDATE `user_account` SET `last_auth_at`={CREATED_AT},`modified_at`={CREATED_AT} WHERE `id`={USER_ID};
        """;

    internal const string INSERT_FEDERATION_ATTEMPT = $"""
        INSERT INTO `federation_request`
          (`uid`,`provider_id`,`application_uid`,`context`,`request_id`,`return_uri`,`state`,`code_challenge`,`created_at`,`expires_at`)
        VALUES ({REQUEST_UID},{PROVIDER_ID},{APPLICATION_UID},{AUDIENCE},{REQUEST_ID},{RETURN_URI},{STATE},{CODE_CHALLENGE},{CREATED_AT},{EXPIRES_AT});
        """;
    internal const string FIND_FEDERATION_ATTEMPT = $"""
        SELECT r.`id` AS local_request_id,r.`uid` AS request_uid,r.`provider_id`,r.`application_uid`,r.`context`,
               r.`request_id`,r.`return_uri`,r.`state`,r.`code_challenge`,r.`expires_at`,p.`uid` AS provider_uid,p.`code` AS provider_code,
               p.`issuer` AS provider_issuer,p.`protocol` AS provider_protocol,i.`config` AS provider_config
          FROM `federation_request` r
          JOIN `identity_provider` p ON p.`id`=r.`provider_id`
          JOIN `identity_provider_info` i ON i.`provider_id`=p.`id`
         WHERE r.`uid`={REQUEST_UID} AND r.`consumed_at` IS NULL AND r.`expires_at`>{CREATED_AT}
           AND p.`status`=2
         LIMIT 1;
        """;
    internal const string INSERT_FEDERATION_REPLAY = $"""
        INSERT IGNORE INTO `federation_replay`
          (`provider_id`,`assertion_hash`,`response_hash`,`expires_at`,`created_at`)
        VALUES ({PROVIDER_ID},{ASSERTION_HASH},{RESPONSE_HASH},{EXPIRES_AT},{CREATED_AT});
        """;
    internal const string CONSUME_FEDERATION_ATTEMPT = $"""
        UPDATE `federation_request` SET `consumed_at`={MODIFIED_AT}
         WHERE `id`={AUTH_REQ_ID} AND `consumed_at` IS NULL AND `expires_at`>{MODIFIED_AT};
        """;
    internal const string INSERT_FEDERATION_HANDOFF = $"""
        INSERT INTO `federation_handoff`
          (`uid`,`auth_req_id`,`application_uid`,`context`,`code_hash`,`payload_enc`,`created_at`,`expires_at`)
        SELECT {HANDOFF_UID},r.`id`,r.`application_uid`,r.`context`,{CODE_HASH},{PAYLOAD_ENC},{CREATED_AT},{EXPIRES_AT}
          FROM `federation_request` r WHERE r.`id`={AUTH_REQ_ID};
        """;
    internal const string FIND_FEDERATION_HANDOFF = $"""
        SELECT h.`id` AS local_handoff_id,h.`uid` AS handoff_uid,h.`application_uid`,h.`context`,h.`payload_enc`,
               r.`code_challenge`,h.`expires_at`
          FROM `federation_handoff` h
          JOIN `federation_request` r ON r.`id`=h.`auth_req_id`
         WHERE h.`application_uid`={APPLICATION_UID} AND h.`code_hash`={CODE_HASH}
           AND r.`code_challenge`={CODE_CHALLENGE}
           AND h.`consumed_at` IS NULL AND h.`expires_at`>{MODIFIED_AT}
         LIMIT 1 FOR UPDATE;
        """;
    internal const string FIND_HANDOFF_FOR_INSPECTION = $"""
        SELECT h.`id` AS local_handoff_id,h.`uid` AS handoff_uid,h.`application_uid`,h.`context`,h.`payload_enc`,
               r.`code_challenge`,h.`expires_at`
          FROM `federation_handoff` h
          JOIN `federation_request` r ON r.`id`=h.`auth_req_id`
         WHERE h.`application_uid`={APPLICATION_UID} AND h.`code_hash`={CODE_HASH}
           AND r.`code_challenge`={CODE_CHALLENGE}
           AND h.`consumed_at` IS NULL AND h.`expires_at`>{MODIFIED_AT}
         LIMIT 1;
        """;
    internal const string CONSUME_FEDERATION_HANDOFF = $"""
        UPDATE `federation_handoff` SET `consumed_at`={MODIFIED_AT}
         WHERE `id`={ID} AND `consumed_at` IS NULL;
        """;
}
