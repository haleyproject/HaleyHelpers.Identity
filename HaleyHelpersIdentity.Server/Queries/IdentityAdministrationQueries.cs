namespace Haley.Internal;

internal static class IdentityAdministrationQueries
{
    internal const string EmailContacts = """
        SELECT c.`uid` AS contact_uid,c.`normalized` AS email,c.`verified_at`,c.`flags` AS contact_flags
          FROM `contact_method` c JOIN `user_account` u ON u.`id`=c.`user_id`
         WHERE u.`uid`=@user AND c.`kind`='email' AND c.`retired_at` IS NULL
         ORDER BY c.`created_at`,c.`id`;
        """;
    internal const string UnverifyEmail = """
        UPDATE `contact_method` SET `verified_at`=NULL,`flags`=(`flags` & 4294967293) WHERE `id`=@id;
        """;
    internal const string CancelEmailChallenges = """
        UPDATE `verification_challenge` c JOIN `challenge_ctx` ctx ON ctx.`challenge_id`=c.`id`
        JOIN `contact_method` email ON email.`id`=@contact
           SET c.`status`=4096,c.`consumed_at`=@at
         WHERE ctx.`subject_uid`=@user AND ctx.`destination_hash`=UNHEX(SHA2(email.`normalized`,256)) AND c.`status`=1;
        """;
    internal const string ExpireEmailGrants = """
        UPDATE `verification_grant` g JOIN `challenge_ctx` ctx ON ctx.`challenge_id`=g.`challenge_id`
        JOIN `contact_method` email ON email.`id`=@contact
           SET g.`expires_at`=LEAST(g.`expires_at`,@at)
         WHERE ctx.`subject_uid`=@user AND ctx.`destination_hash`=UNHEX(SHA2(email.`normalized`,256)) AND g.`consumed_at` IS NULL;
        """;
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
