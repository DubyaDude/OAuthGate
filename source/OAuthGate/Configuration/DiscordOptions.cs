namespace NginxOAuth.Configuration
{
    public class DiscordOptions
    {
        public DiscordClientOptions Client { get; set; } = new();
        public ulong[]? WhitelistedGuilds { get; set; } = null;
        public ulong[]? WhitelistedUsers { get; set; } = null;
    }

    public class DiscordClientOptions
    {
        public ulong? Id { get; set; } = null;
        public string? Secret { get; set; } = null;
    }
}
