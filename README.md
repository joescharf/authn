# Authentication Libraries

## Intro

A quick and dirty auth library to authenticate JWTs and perform
user/pass authentication for a few Authentication services

## Auth0

```
AUTH0_AUD_API_IDENTIFIER: "https://api.example.com"
AUTH0_ISS_DOMAIN: "https://example.us.auth0.com/"
AUTH0_CLIENT_ID: "ASSIGNED_CLIENT_ID"
AUTH0_CLIENT_SECRET: "ASSIGNED_SECRET"
AUTH0_DB_CONNECTION: "database_connetion_name"
```

## Releasing with go-releaser:

```sh
# Make changes, commit changes...
# tag it, push it
git tag -a v0.1.0 -m "Comment"
git push origin v0.1.0

# dry run
goreleaser release --snapshot --skip-publish --rm-dist

# Real deal
GITHUB_TOKEN=XXX goreleaser --rm-dist

```
