namespace Haley.Internal;

internal static class IdentityAccountQueries
{
    internal const string FindEmail = """
        SELECT DISTINCT u.`id` AS local_user_id,u.`uid` AS user_uid,u.`display_name`,u.`status`,
               u.`normalized`,u.`flags`,u.`created_at`,u.`last_auth_at`
          FROM `user_account` u LEFT JOIN `contact_method` c ON c.`user_id`=u.`id` AND c.`kind`='email' AND c.`retired_at` IS NULL
         WHERE c.`normalized`=@email OR u.`normalized`=@email
         ORDER BY u.`id` LIMIT 2;
        """;
    internal const string FindEmailForUpdate = """
        SELECT DISTINCT u.`id` AS local_user_id,u.`uid` AS user_uid,u.`display_name`,u.`status`,
               u.`normalized`,u.`flags`,u.`created_at`,u.`last_auth_at`
          FROM `user_account` u LEFT JOIN `contact_method` c ON c.`user_id`=u.`id` AND c.`kind`='email' AND c.`retired_at` IS NULL
         WHERE c.`normalized`=@email OR u.`normalized`=@email
         ORDER BY u.`id` LIMIT 2 FOR UPDATE;
        """;
    internal const string FindUserForUpdate = """
        SELECT u.`id` AS local_user_id,u.`uid` AS user_uid,u.`display_name`,u.`status`,
               u.`normalized`,u.`flags`,u.`created_at`,u.`last_auth_at`
        FROM `user_account` u WHERE u.`uid`=@uid LIMIT 1 FOR UPDATE;
        """;
    internal const string TouchAccount = """
        UPDATE `user_account` SET `last_auth_at`=@at WHERE `id`=@user;
        """;
    internal const string InsertAccount = """
        INSERT IGNORE INTO `user_account` (`uid`,`status`,`normalized`,`display_name`,`flags`,`created_at`,`modified_at`)
        VALUES (@uid,2,@email,@display,1,@at,@at) RETURNING `id`;
        """;
    internal const string InsertContact = """
        INSERT IGNORE INTO `contact_method` (`uid`,`user_id`,`kind`,`normalized`,`display`,`flags`,`created_at`)
        VALUES (@uid,@user,'email',@email,@email,0,@at);
        """;
    internal const string FindOrigin = """
        SELECT u.`uid` AS user_uid FROM `user_origin` o JOIN `user_account` u ON u.`id`=o.`user_id`
        WHERE o.`application_uid`=@application AND o.`origin`='application' AND o.`source_hash`=@hash
        LIMIT 1 FOR UPDATE;
        """;
    internal const string InsertOrigin = """
        INSERT IGNORE INTO `user_origin` (`user_id`,`application_uid`,`origin`,`source_hash`,`created_at`)
        VALUES (@user,@application,'application',@hash,@at);
        """;
    internal const string FindCurrentCredential = """
        SELECT `id` FROM `credential` WHERE `user_id`=@user AND `kind`='password'
        AND `status`=2 AND `retired_at` IS NULL ORDER BY `id` DESC LIMIT 1 FOR UPDATE;
        """;
    internal const string InsertSession = """
        INSERT INTO `user_session` (`uid`,`user_id`,`application_uid`,`kind`,`status`,`expires_at`)
        VALUES (@uid,@user,@application,@kind,2,@expires) RETURNING `id`;
        """;
    internal const string InsertSessionInfo = """
        INSERT INTO `user_session_info` (`session_id`,`auth_time`,`last_seen_at`,`auth_methods`,`ip_hash`,`user_agent_hash`,`device_hash`)
        VALUES (@session,@at,@at,@methods,@ip,@agent,@device);
        """;
    internal const string InsertSessionToken = """
        INSERT INTO `user_session_token` (`session_id`,`token_hash`) VALUES (@session,@hash);
        """;
    internal const string ValidateSession = """
        SELECT s.`uid` AS session_uid,s.`expires_at`
        FROM `user_session_token` t JOIN `user_session` s ON s.`id`=t.`session_id`
        JOIN `user_account` u ON u.`id`=s.`user_id`
        WHERE t.`token_hash`=@hash AND s.`application_uid`=@application AND s.`kind`=1
          AND s.`status`=2 AND s.`expires_at`>@at AND u.`status`=2 LIMIT 1;
        """;
    internal const string RevokeSession = """
        UPDATE `user_session` s JOIN `user_session_token` t ON t.`session_id`=s.`id`
        SET s.`status`=64,s.`ended_at`=COALESCE(s.`ended_at`,@at)
        WHERE t.`token_hash`=@hash AND s.`application_uid`=@application AND s.`kind`=1;
        """;
    internal const string PasswordHistory = """
        SELECT `secret_hash`,`algorithm`,`params` FROM `password_history`
        WHERE `user_id`=@user ORDER BY `id` DESC LIMIT @count;
        """;
    internal const string CurrentCredentialByUser = """
        SELECT u.`id` AS local_user_id,c.`id` AS local_credential_id,c.`uid` AS credential_uid,
               c.`secret_hash`,c.`algorithm`,c.`params`
        FROM `user_account` u LEFT JOIN `credential` c ON c.`user_id`=u.`id`
             AND c.`kind`='password' AND c.`status`=2 AND c.`retired_at` IS NULL
        WHERE u.`uid`=@uid AND u.`status`<>4 ORDER BY c.`id` DESC LIMIT 1 FOR UPDATE;
        """;
}
