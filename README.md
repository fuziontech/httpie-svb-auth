# httpie-svb-auth

[SVB API](http://docs.svbplatform.com/) auth plugin for
[HTTPie](https://httpie.org/).

# Installation

Install with `pip` to make this plugin available to HTTPie.

```sh
pip install httpie-svb-auth
```

You should now see `svb` as an available auth type when you run `http --help`.

# Usage

Use HTTPie as you normally would, except pass `svb` as the auth type and pass
your API key and HMAC secret as your auth info (username and password,
respectively). For example:

```sh
http -A svb -a "${SVB_API_KEY}:${SVB_HMAC_SECRET}" https://api.svb.com/
```

For local dev of the api you should use this:
```sh
http -A svb -a "keyid=${SVB_KEY_ID}:${SVB_HMAC_SECRET}" http://127.0.0.1:4000/
```

# License

Copyright (c) 2017 Silicon Valley Bank. Distributed under the MIT License.
