# NGINX Discord OAuth Reverse Proxy

This project allows one to secure a NGINX reverse proxied site via Discord OAuth.

## Setting up OAuth Process

### appsettings.json
Configure the `appsettings.json` like so:
```json
"DiscordOptions": {
  "Client": {
    "Id": 0,
    "Secret": "0"
  },
  "WhitelistedServers": [ 0, 1 ],
  "WhitelistedUsers": [ 0, 1 ]
}
```
- Client.Id: The Client ID of the Discord Application.

- Client.Secret: The Secret of the Discord Application.

- WhitelistedGuilds: Whitelisted Discord Guild Ids. (The needs to be part of the guild)

- WhitelistedUsers: Whitelisted Discord Discord User Ids.

**Whitelist Behaviour** - A user must be part of either Whitelisted Guilds or Whitelisted Users if either one has a value. If both are null/empty, any Discord Login will be allowed.

### Running on Dfferent Port
To run the process on a specific port, start the OAuth project like so:
```
./OAuth --urls=https://localhost:7161
```

## Setting up NGINX Config

Use the [nginx.conf](https://github.com/DubyaDude/nginx-discord-oauth-reverse-proxy/blob/master/nginx.conf) file in the repos root and replace any instance of `https://localhost:7161` if you end up using a different port.
