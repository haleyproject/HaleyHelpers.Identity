namespace Haley.DAL;
internal static class IdentityDatabase
{
    public const string SchemaResource = "Haley.Identity.Database.MariaDB.schema.sql";
    public const string SeedResource = "Haley.Identity.Database.MariaDB.seed.sql";
    public static byte[] ToBinary(Guid value) => Convert.FromHexString(value.ToString("N"));
    public static Guid FromBinary(byte[] value)
    {
        if (value.Length != 16)
        {
            throw new InvalidDataException("An Identity public identifier must contain exactly 16 bytes.");
        }

        return Guid.ParseExact(Convert.ToHexString(value), "N");
    }
}
