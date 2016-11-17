[![Build Status](https://travis-ci.org/mendersoftware/useradm.svg?branch=master)](https://travis-ci.org/mendersoftware/useradm)
[![codecov](https://codecov.io/gh/mendersoftware/useradm/branch/master/graph/badge.svg)](https://codecov.io/gh/mendersoftware/useradm)
[![Go Report Card](https://goreportcard.com/badge/github.com/mendersoftware/useradm)](https://goreportcard.com/report/github.com/mendersoftware/useradm)
[![Docker pulls](https://img.shields.io/docker/pulls/mendersoftware/useradm.svg?maxAge=3600)](https://hub.docker.com/r/mendersoftware/useradm/)

Mender: User Administration Service
==============================================

Mender is an open source over-the-air (OTA) software updater for embedded Linux
devices. Mender comprises a client running at the embedded device, as well as
a server that manages deployments across many devices.

This repository contains the Mender User Administration Service, which is part of the
Mender server. The Mender server is designed as a microservices architecture
and comprises several repositories.

The User Administration Service is allows for user managment and authentication.

![Mender logo](https://mender.io/user/pages/04.resources/_logos/logoS.png)


## Getting started

To start using Mender, we recommend that you begin with the Getting started
section in [the Mender documentation](https://docs.mender.io/).


## Building from source

As the Mender server is designed as microservices architecture, it requires several
repositories to be built to be fully functional. If you are testing the Mender server it
is therefore easier to follow the getting started section above as it integrates these
services.

If you would like to build the Device Inventory service independently, you can follow
these steps:

```
git clone https://github.com/mendersoftware/useradm.git
cd useradm
go build
```

## Configuration

The service can be configured by:
* providing configuration file (supports JSON, TOML, YAML and HCL formatting).
The default configuration file is provided to be downloaded from [config.yaml](https://github.com/mendersoftware/inventory/blob/master/config.yaml).
* setting environment variables. The service will check for a environment variable
with a name matching the key uppercased and prefixed with "USERADM_".
Eg. for "listen" the variable name is "USERADM_LISTEN".

## Contributing

We welcome and ask for your contribution. If you would like to contribute to Mender, please read our guide on how to best get started [contributing code or
documentation](https://github.com/mendersoftware/mender/blob/master/CONTRIBUTING.md).

## License

Mender is licensed under the Apache License, Version 2.0. See
[LICENSE](https://github.com/mendersoftware/useradm/blob/master/LICENSE) for the
full license text.

## Security disclosure

We take security very seriously. If you come across any issue regarding
security, please disclose the information by sending an email to
[security@mender.io](security@mender.io). Please do not create a new public
issue. We thank you in advance for your cooperation.

## Connect with us

* Join our [Google
  group](https://groups.google.com/a/lists.mender.io/forum/#!forum/mender)
* Follow us on [Twitter](https://twitter.com/mender_io?target=_blank). Please
  feel free to tweet us questions.
* Fork us on [Github](https://github.com/mendersoftware)
* Email us at [contact@mender.io](mailto:contact@mender.io)