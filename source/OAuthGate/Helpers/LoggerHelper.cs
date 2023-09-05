using Serilog;
using Serilog.Events;

namespace NginxOAuth.Helpers
{
    public static class LoggerHelper
    {
        public static readonly Microsoft.Extensions.Logging.ILogger GlobalLogger = BuildLoggerFactory().CreateLogger("");

        public static ILoggerFactory BuildLoggerFactory(string? sourceContext = null)
        {
            return new LoggerFactory().AddSerilog(logger: new LoggerConfiguration()
                    .MinimumLevel.Is(LogEventLevel.Information)
                    .WriteTo.Console(outputTemplate: "[{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz}] [{Level:u4}] " + (sourceContext ?? "{SourceContext}") + ": {Message:lj}{NewLine}{Exception}")
                    .CreateLogger());
        }
    }
}
