namespace NginxOAuth.Configuration
{
    public class DiscordOptions
    {
        public string AuthCookieName { get; set; } = "APP_NAME_HERE-auth";
        public DiscordClientOptions Client { get; set; } = new();
        public ulong[]? WhitelistedGuilds { get; set; } = null;
        public ulong[]? WhitelistedUsers { get; set; } = null;
        public ContentHandling EmailHandling { get; set; } = ContentHandling.None;
    }

    public class DiscordClientOptions
    {
        public ulong? Id { get; set; } = null;
        public string? Secret { get; set; } = null;
    }

    public enum ContentHandling
    {
        None,
        Log,
        LogAndRequire
    }
}
