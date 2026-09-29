namespace Haley.Internal;

internal static class IdentityAdministrationQueries
{
    internal const string Sessions = """
        SELECT s.`uid` AS session_uid,u.`uid` AS user_uid,s.`application_uid`,s.`status`,s.`expires_at`,s.`ended_at`,i.`auth_time`,i.`last_seen_at`
          FROM `user_session` s JOIN `user_account` u ON u.`id`=s.`user_id`
          JOIN `user_session_info` i ON i.`session_id`=s.`id`
         WHERE u.`uid`=@user AND (@active=0 OR (s.`status`=2 AND s.`expires_at`>@at))
         ORDER BY i.`auth_time` DESC,s.`id` DESC LIMIT @limit OFFSET @offset;
        """;
    internal const string RevokeSession = """
        UPDATE `user_session` SET `status`=64,`ended_at`=COALESCE(`ended_at`,@at) WHERE `uid`=@uid AND `status`=2;
        """;
}
