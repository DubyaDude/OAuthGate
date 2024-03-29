# OAuthGate - A NGINX Discord OAuth Reverse Proxy

This project allows securing an NGINX reverse proxied site via Discord OAuth.

## Setting up OAuthGate Process

### appsettings.json
Configure the `appsettings.json` like so:
```json
"DiscordOptions": {
  "AuthCookieName": "APP_NAME_HERE-auth",
  "Client": {
    "Id": 0,
    "Secret": "0"
  },
  "WhitelistedUsers": [ 0, 1 ],
  "WhitelistedGuilds": [ 0, 1 ],
  "WhitelistedRoles": {
      "0": [ 1, 2 ],
      "3": [ 4, 5 ]
    },
  "EmailHandling":  "None"
}
```
- AuthCookieName: The name of the Authentication Cookie.

- Client.Id: The Client ID of the Discord Application.

- Client.Secret: The Secret of the Discord Application.

- WhitelistedUsers: Whitelisted Discord Discord User IDs.

- WhitelistedGuilds: Whitelisted Discord Guild IDs. (They need to be part of the guild)

- WhitelistedRoles: Whitelisted Discord Guild Role Ids. (They need to be part of the guild and have the role)

- EmailHandling: How to handle email
  - None: Do not ask for an email when calling Discord OAuth.
  - Log: Ask for email when calling Discord OAuth.
  - LogAndRequire: Ask for email when calling Discord OAuth and check that an email was given from the callback.

**Whitelist Behaviour** - A user must be part of either Whitelisted Guilds, Whitelisted Roles, or Whitelisted Users if either one has a value. If all are null/empty, any Discord Login will be allowed.

### Running on Different Port
To run the process on a specific port, start the OAuthGate project like so:
```
./OAuthGate --urls=https://localhost:7161
```

## Setting up NGINX Config

Use the [nginx.conf](https://github.com/DubyaDude/nginx-discord-oauth-reverse-proxy/blob/master/nginx.conf) file in the root of the repo and replace any instance of `https://localhost:7161` if you end up using a different port.
