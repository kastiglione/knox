# knox

Tools to repurpose system auditing for non-security uses. Allows observability and introspection into processes and their lifecycle, granular file access, causes or sources of errors, info about networking use, and more. Based on macOS system auditing API ["Basic Security Module" (aka BSM)](https://en.wikipedia.org/wiki/OpenBSM).

## Introduction

macOS has a system library called `libbsm`, which is a lesser known API for security auditing and monitoring. This same data is potentially useful for much more. Like what exactly? Well, that's why this repo exists -- to explore the possibilities and to provide tools, libraries, and documentation for working with `libbsm`.

Some interesting uses for `libbsm` are: observing and reacting to process lifecycle, visualizing file access across the life of a process, visibility of internal process errors, etc. This kind of data has been available via `dtrace`, using `libbsm` is still interesting because it has different programming ergonomics, and has different tradeoffs.

## Install

```sh
brew install --HEAD kastiglione/formulae/knox
```

## Tools

### `auditpipe`

Opens and configures the audit event firehose: `/dev/auditpipe`. The `auditpipe` command takes a set of event classes, and writes all matching events to `stdout`. A quick example to consider:

```sh
sudo auditpipe pc,fc | praudit -lx
```

Using `praudit` (ships with macOS), this prints process events ("pc" event class) and file creation events ("fc" event class). See [Event Classes](#event-classes) for a list. The process event class includes syscalls such as `fork`, `execve`, `posix_spawn`, `kill`, `exit`, and more. The syscalls and their associated event classes are listed in `/etc/security/audit_event`.

As described in `man audit_control`, event classes can be formatted as "comma-delimited list". Additionally, event classes can be prefixed with `+` to show only successful events, or `-` to show only failed events. See "Audit Flags" in `man audit_control` for full details.

The complete list of event classes can be found in `/etc/security/audit_classes`. See [Event Classes](#event-classes) for an overview:

#### Examples

##### Print successful process events:

```sh
sudo auditpipe +pc | praudit -lx
```

##### Print failed file reads and writes, and filters to the given path prefix:

```sh
sudo auditpipe -fr,-fw | praudit -lx | grep /Users/me
```

### `commands`

If you ever need to see which commands are being run by other processes, this is the tool to do that. Prints the command lines for all processes. The `commands` tool reads from either `auditpipe` or from `/var/audit` logs.

#### Examples

```sh
sudo auditpipe +pc | commands
sudo commands /var/audit/current
```

### `auditon`

The `auditon` command is a command line interface to the `auditon(2)` API. It's useful for some advanced use cases (TODO: document these). See the source and man page for details.

## Audit Log

`/dev/auditpipe` is useful for live observing events. Additionally, BSM can also be configured to log events to `/var/audit`, and this is useful to look back in time for events matching some criteria. To configure the audit logs, see `man audit_control` and edit `/etc/security/audit_control`. Note that some settings take effect on login, so logout/login can be required to have settings take effect. Other settings, such as file size limits, can be applied by running `sudo audit -s`.

## Documentation

The majority of documentation is in the BSM headers (`bsm/libbsm.h`) and manual pages (see below). Most of the Audit man pages are available only when Xcode is installed. The [xnu source](https://opensource.apple.com/tarballs/xnu/) can also be hepful.

* `man auditpipe`
* `man audit.log`
* `man audit_class`
* `man audit_control`
* `man praudit`
* `man auditon`
* `man auditreduce`

`grep` can find more `man` pages:

```
cd $(xcrun --show-sdk-path)/usr/share/man
grep -rl '\bau_' .
```

#### Limitiations

* The audit token for exec args is limited to a max of 128 arguments
* During high load, `/dev/auditpipe` can drop events if its queue is full
* `/dev/auditpipe` provides events for the current user, not `root`

## Event Classes

| Name | Description |
| --- | --- |
| fr | file read |
| fw | file write |
| fa | file attribute access |
| fm | file attribute modify |
| fc | file create |
| fd | file delete |
| cl | file close |
| pc | process |
| nt | network |
| ip | ipc |
| ad | administrative |
| lo | login_logout |
| aa | authentication and authorization |
| ap | application |
| io | ioctl |
| ex | exec |
| ot | miscellaneous |
| all | all flags set |

## Permissions

Root permissinos are required to access `/dev/auditpipe` and the logs in `/var/audit`. To avoid needing a password to use these, there are two options:

1. Make the binaries setuid
2. Add config in `/etc/sudoers`

#### setuid

To make `auditpipe` setuid, run:

```sh
sudo chown root auditpipe
sudo chmod +s auditpipe
```

#### sudo

Shell aliases can be used to always use `sudo`:

```sh
alias auditpipe='sudo auditpipe'
```

To make `sudo auditpipe` require no password, run `sudo visudo` and then add:

```
yourusername	ALL = NOPASSWD: /usr/local/bin/auditpipe *
```

## Why "knox"

The Audit API types and functions are prefixed with "au", and Au is the chemical symbol for gold. One place to find gold is at Fort Knox. But really, all of this provides a line of reasoning to pay some small homage to my super awesome grandma, whose maiden name was Knox.
