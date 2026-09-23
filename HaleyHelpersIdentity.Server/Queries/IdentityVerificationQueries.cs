namespace Haley.Internal;

internal static class IdentityVerificationQueries
{
    private const string Subject = """
        SELECT u.`id` AS local_user_id,u.`uid` AS user_uid,u.`display_name`,u.`status`,u.`normalized`,
               u.`flags`,u.`created_at`,u.`last_auth_at`,c.`uid` AS contact_uid,c.`normalized` AS email,
               c.`verified_at`,c.`flags` AS contact_flags,p.`uid` AS credential_uid
        FROM `user_account` u JOIN `contact_method` c ON c.`user_id`=u.`id`
        LEFT JOIN `credential` p ON p.`user_id`=u.`id` AND p.`kind`='password' AND p.`status`=2 AND p.`retired_at` IS NULL
        WHERE c.`kind`='email' AND c.`retired_at` IS NULL
        """;
    internal const string ByEmail = Subject + " AND c.`normalized`=@email ORDER BY p.`id` DESC LIMIT 1;";
    internal const string ByDestination = Subject + " AND u.`uid`=@uid AND UNHEX(SHA2(c.`normalized`,256))=@destination ORDER BY p.`id` DESC LIMIT 1;";
    internal const string LockSubject = Subject + " AND u.`uid`=@uid AND c.`uid`=@contact ORDER BY p.`id` DESC LIMIT 1 FOR UPDATE;";
    internal const string VerifyContact = """
        UPDATE `contact_method` SET `verified_at`=COALESCE(`verified_at`,@at),`flags`=(`flags` | 2)
        WHERE `uid`=@contact AND `retired_at` IS NULL;
        """;
    internal const string ClearContactVerificationPending = """
        UPDATE `user_account` u SET u.`flags`=(u.`flags` & 4294967291),u.`modified_at`=@at
        WHERE u.`uid`=@uid AND NOT EXISTS (
            SELECT 1 FROM `contact_method` c WHERE c.`user_id`=u.`id` AND c.`kind`='email'
              AND c.`retired_at` IS NULL AND c.`verified_at` IS NULL);
        """;
    internal const string ActivateAccount = """
        UPDATE `user_account` SET `status`=2,`flags`=(`flags` & 4294967291),`modified_at`=@at
        WHERE `uid`=@uid AND `status`=1;
        """;
}
