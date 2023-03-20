using Microsoft.AspNetCore.HttpOverrides;
using NginxOAuth.Helpers;

#if DEBUG
LoggerHelper.GlobalLogger.LogWarning("This is DEBUG, please make sure this is not running in a production environment");
#else
LoggerHelper.GlobalLogger.LogWarning("This is NOT DEBUG, testing locally may not work as expected");
#endif

var builder = WebApplication.CreateBuilder(args);
// Add services to the container.

builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
});

builder.Services.AddOAuth(builder.Configuration);

var app = builder.Build();

app.UseForwardedHeaders();

app.ConfigureOAuth();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();

app.UseRouting();

app.Run();
