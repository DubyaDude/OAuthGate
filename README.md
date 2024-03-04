# OAuthGate - A NGINX Discord OAuth Reverse Proxy

This project allows one to secure a NGINX reverse proxied site via Discord OAuth.

## Setting up OAuthGate Process

### appsettings.json
Configure the `appsettings.json` like so:
```json
"DiscordOptions": {
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
- Client.Id: The Client ID of the Discord Application.

- Client.Secret: The Secret of the Discord Application.

- WhitelistedUsers: Whitelisted Discord Discord User Ids.

- WhitelistedGuilds: Whitelisted Discord Guild Ids. (They need to be part of the guild)

- WhitelistedRoles: Whitelisted Discord Guild Role Ids. (They need to be part of the guild and have the role)

- EmailHandling: How to handle email
  - None: Do not ask for email when calling Discord OAuth.
  - Log: Ask for email when calling Discord OAuth.
  - LogAndRequire: Ask for email when calling Discord OAuth and check that an email was given from the callback.

**Whitelist Behaviour** - A user must be part of either Whitelisted Guilds or Whitelisted Users if either one has a value. If both are null/empty, any Discord Login will be allowed.

### Running on Dfferent Port
To run the process on a specific port, start the OAuthGate project like so:
```
./OAuthGate --urls=https://localhost:7161
```

## Setting up NGINX Config

Use the [nginx.conf](https://github.com/DubyaDude/nginx-discord-oauth-reverse-proxy/blob/master/nginx.conf) file in the repos root and replace any instance of `https://localhost:7161` if you end up using a different port.
