using AspNet.Security.OAuth.Discord;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Authorization;
using Newtonsoft.Json.Linq;
using NginxOAuth.Configuration;
using NginxOAuth.Helpers;
using System.Net.Http.Headers;
using System.Net.Mime;
using System.Security.Claims;

namespace Microsoft.Extensions.DependencyInjection
{
    public static class OAuthGate
    {
        private const string CookieName = "APP_NAME_HERE-auth";

        private const string RootPath = "/";
        private const string AuthRootPath = "/auth";
        private const string LoginPath = AuthRootPath + "/login";
        private const string LogoutPath = AuthRootPath + "/logout";
        private const string CallbackPath = AuthRootPath + "/callback";
        private const string CallbackDonePath = AuthRootPath + "/callbackdone";
        private const string AuthCheckPath = "/is_authed";

        private const string GuildClaim = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/guilds";

        public static void AddOAuthGate(this IServiceCollection services, IConfiguration configuration)
        {
            var config = configuration.GetSection(nameof(DiscordOptions)).Get<DiscordOptions>();

            services.AddAuthorization(options =>
            {
                var policy = new AuthorizationPolicyBuilder()
                    .RequireAuthenticatedUser();

                IEnumerable<string>? whitelistedUsers = config?.WhitelistedUsers != null && config.WhitelistedUsers.Length > 0 ? config.WhitelistedUsers.Select(x => x.ToString()) : null;
                IEnumerable<string>? whitelistedGuilds = config?.WhitelistedGuilds != null && config.WhitelistedGuilds.Length > 0 ? config.WhitelistedGuilds.Select(x => x.ToString()) : null;

                if (whitelistedUsers != null || whitelistedGuilds != null)
                {
                    policy.RequireAssertion(context =>
                    {
                        if (whitelistedUsers != null)
                        {
                            if (whitelistedUsers.Any(id => context.User.HasClaim(ClaimTypes.NameIdentifier, id)))
                            {
                                return true;
                            }
                        }

                        if (whitelistedGuilds != null)
                        {
                            if (whitelistedGuilds.Any(id => context.User.HasClaim(GuildClaim, id)))
                            {
                                return true;
                            }
                        }

                        return false;
                    });
                }

                options.FallbackPolicy = policy
                    .Build();
            });
            services.AddAuthentication(options =>
                {
                    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                    options.DefaultChallengeScheme = DiscordAuthenticationDefaults.AuthenticationScheme;
                })
                .AddCookie(options =>
                {
                    options.Cookie.Name = CookieName;
#if !DEBUG
                    options.Cookie.SameSite = SameSiteMode.Strict;
                    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
#endif
                    options.LoginPath = new PathString(LoginPath);
                    options.LogoutPath = new PathString(LogoutPath);

                    options.Events.OnRedirectToAccessDenied = async context => await OnAuthFail(context.HttpContext, context.Response);
                })
                .AddDiscord(options =>
                {
#if !DEBUG
                    options.CorrelationCookie.SecurePolicy = CookieSecurePolicy.Always;
#endif
                    options.SaveTokens = true;

                    options.ClientId = config?.Client.Id?.ToString() ?? throw new InvalidOperationException("You need to set Client Id");
                    options.ClientSecret = config?.Client.Secret ?? throw new InvalidOperationException("You need to set Client Secret");
                    options.CallbackPath = new PathString(CallbackPath);

                    options.Scope.Add("identify");
                    options.Scope.Add("email");
                    options.Scope.Add("guilds");

                    options.ClaimActions.MapJsonKey(ClaimTypes.NameIdentifier, "id");
                    options.ClaimActions.MapJsonKey(ClaimTypes.Name, "username");
                    options.ClaimActions.MapJsonKey("urn:discord:avatar", "avatar");
                    options.ClaimActions.MapJsonKey(ClaimTypes.Email, "email");

                    options.Events.OnCreatingTicket = async context => await OnCreatingTicket(context);
                    options.Events.OnRemoteFailure = async context => await OnAuthFail(context.HttpContext, context.Response);
                });
        }

        private static async Task OnCreatingTicket(OAuthCreatingTicketContext context)
        {
            LogRequest("Creating Ticket", context.HttpContext, context.Identity?.Claims);

            var request = new HttpRequestMessage(HttpMethod.Get, "https://discordapp.com/api/users/@me/guilds");

            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(MediaTypeNames.Application.Json));
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", context.AccessToken);

            var response = await context.Backchannel.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, CancellationToken.None);
            if (!response.IsSuccessStatusCode)
            {
                throw new HttpRequestException("Failed to get guilds");
            }

            var responseString = (await response.Content.ReadAsStringAsync());
            LogRequest($"Guilds Return: {responseString}", context.HttpContext, context.Identity?.Claims);
            var payload = JArray.Parse(responseString).Select(j => j["id"]?.ToString());
            if (payload != null)
            {
                foreach (var id in payload)
                {
                    if (id != null)
                    {
                        Claim claim = new(GuildClaim, id, ClaimValueTypes.String);
                        context?.Identity?.AddClaim(claim);
                    }
                }
            }
        }

        public static WebApplication ConfigureOAuth(this WebApplication app)
        {
            app.UseAuthentication();

            app.Map(CallbackDonePath, appBuilder =>
            {
                appBuilder.Run(async context =>
                {
                    LogRequest("Callback Done", context, context.User.Claims);

                    var returnurl = context.Request.Query["ReturnUrl"];
                    if (string.IsNullOrEmpty(returnurl))
                        returnurl = RootPath;

                    context.Response.Headers.Add("Refresh", $"0; url={returnurl}");
                    context.Response.StatusCode = StatusCodes.Status200OK;

                    await Task.CompletedTask;
                });
            });

            app.Map(LoginPath, appBuilder =>
            {
                appBuilder.Run(async context =>
                {
                    LogRequest("Login", context, context.User.Claims);

                    var returnurl = context.Request.Query["ReturnUrl"];
                    if (string.IsNullOrEmpty(returnurl))
                        returnurl = RootPath;

                    await context.ChallengeAsync(DiscordAuthenticationDefaults.AuthenticationScheme, new AuthenticationProperties()
                    {
                        RedirectUri = $"{CallbackDonePath}?ReturnUrl={returnurl}",
                    });
                });
            });

            app.Map(LogoutPath, appBuilder =>
            {
                appBuilder.Run(async context =>
                {
                    LogRequest("Logout", context, context.User.Claims);

                    context.Response.Cookies.Delete(CookieName);
                    await context.SignOutAsync();

                    await WriteResponse(context.Response, StatusCodes.Status200OK, "Signed Out");
                });
            });

            app.Map("/robots.txt", appBuilder =>
            {
                appBuilder.Run(async context =>
                {
                    LogRequest("Robots.txt", context, context.User.Claims);

                    context.Response.ContentType = MediaTypeNames.Text.Plain;
                    context.Response.StatusCode = StatusCodes.Status200OK;
                    await context.Response.WriteAsync("User-agent: *  \nDisallow: /");
                });
            });

            app.UseAuthorization();

            app.MapWhen(
                ctx => ctx.Request.Path == RootPath || ctx.Request.Path == AuthCheckPath,
                appBuilder =>
                {
                    appBuilder.Run(async context =>
                    {
                        LogRequest("Authentication Check", context, context.User.Claims);

                        await WriteResponse(context.Response, StatusCodes.Status200OK, "Ok");
                    });
                });

            return app;
        }

        private static async Task OnAuthFail(HttpContext context, HttpResponse response)
        {
            LogRequest("Authentication Fail", context, context.User.Claims);

            await WriteResponse(response, StatusCodes.Status403Forbidden, "Authentication Failed");
        }

        private static async Task WriteResponse(HttpResponse response, int statusCode, string message)
        {
            response.ContentType = MediaTypeNames.Text.Html;
            response.StatusCode = statusCode;
            await response.WriteAsync(
                "<!DOCTYPE html><html><head><meta charset=\"utf-8\"></head><body>" +
                $"<h1>{message}</h1>" +
                "</body></html>");
        }

        private static void LogRequest(string message, HttpContext context, IEnumerable<Claim>? claims)
        {
            string? id = claims?.FirstOrDefault(x => x.Type == ClaimTypes.NameIdentifier)?.Value;
            string? name = claims?.FirstOrDefault(x => x.Type == ClaimTypes.Name)?.Value;
            string? email = claims?.FirstOrDefault(x => x.Type == ClaimTypes.Email)?.Value;

            string? ip = context.Connection?.RemoteIpAddress?.ToString();

            if (context.Request.Headers.TryGetValue("CF-Connecting-IP", out var values))
            {
                string originalIps = string.Join(", ", values);
                LoggerHelper.GlobalLogger.LogInformation("ID:[{id}] Name:[{name}] Email:[{email}] IP:[{ip}] CloudflareIP:[{cfIp}] :: {message}", id, name, email, originalIps, ip, message);
            }
            else
            {
                LoggerHelper.GlobalLogger.LogInformation("ID:[{id}] Name:[{name}] Email:[{email}] IP:[{ip}] :: {message}", id, name, email, ip, message);
            }
        }
    }
}
