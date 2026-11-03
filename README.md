> [!NOTE]
> This is mirrored from my private forgejo instance

# Zitadel Glauth Plugin

This is a very simple, and very YOLO plugin for Zitadel.

## How does it work?

Querying the Zitadel API for every single LDAP query is pretty slow.

So it basically shlurps users and their grants and metadata into memory and then operates on that.
The in memory data is updated either:

* every 10 minutes
* everytime a bind happens (async)

Also because a password check is pretty slow via the session API and every single LDAP query will do a bind, the password and username pairs are hashed and cached for 1h.

## How to use it?

Create a service account, give it `Org User Manager`. Then create a personal access token for that account.

Set these env variables:

```
export ZITADEL_URL=https://...
export ZITADEL_PAT=....
```

The plugin can handle capabilities and custom fields.

To add capability `search *` to a user, set metadata `cap_search` with the value of `*`.

To add a custom field called `test` to a user, set the metadata `gl_test` with any desired value.

### Security options

| Variable | Default | Effect |
|---|---|---|
| `ZITADEL_LDAP_ENABLE_WRITES` | `false` | Enables LDAP Add/Modify/Delete. When off, every write returns `insufficientAccessRights`. |
| `ZITADEL_LDAP_ALLOW_ANONYMOUS_BIND` | `true` | Set to `false` to reject anonymous binds. |
| `ZITADEL_LDAP_LOGIN_CACHE_TTL` | `60s` | How long a *successful* bind is cached (Go duration; `0` disables). Failures are never cached. |

Writes also require the bound user to have the `cap_write` metadata (value `*`), and the target DN must be
`cn=<user>,ou=users,<baseDN>`. Writes act with the service account's privileges, so grant `cap_write` sparingly.
Empty-password binds are rejected.

### Dynamic groups (filter-based)

You can define dynamic groups in the config by attaching a `dynamicFilter` capability to a group.
The filter is evaluated against user attributes and decoded metadata (including `gl_` keys).

Example:

```toml
[[groups]]
	name = "eng"
	gidnumber = 9001
	[[groups.capabilities]]
		action = "dynamicFilter"
		object = "(gl_department=engineering)"
```

The plugin will only show human users in the LDAP queries!

> [!CAUTION]
> Make sure that you don't have duplicated role names in your projects! The plugin will put them all in the same ou, so they can't have the same names!

## Disclaimer

Use this thing on your own risk! I'm not responsible if it eats your cat or let's all the hackers into your systems.
