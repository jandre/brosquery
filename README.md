## What?

It's a module for loading `bro` logs as tables in osquery.

The logs are dynamically loaded from the `bro` logs installation directory and created as tables pre-pended with `bro_`.
E.g., `conn.log` -> table `bro_conn`

## Example

![screenshot](https://raw.githubusercontent.com/jandre/brosquery/master/screenshot.png)

From EnvDB UI:

![screenshot](https://raw.githubusercontent.com/jandre/brosquery/master/envdb-screenshot.png)

## Building and Installing

```bash
make deps
make
```

This will create the module `./build/src/libbro.<dylib|so>`

You will then need to copy this to `/usr/local/lib/libbro.<dylib|so>` and then you can add an entry to `/etc/osquery/modules.load`:

```bash
$ sudo cp -r ./build/src/libbro.<dylib|so> /usr/local/lib
$ sudo mkdir -p /etc/osquery/
$ sudo sh -c 'echo "/usr/local/lib/libbro.<so|dylib>" >> /etc/osquery/modules.load'
```

You can now run `osqueryi` with the location of `$BROPATH` set to the bro path, where it will attempt to load log tables from `$BROPATH/logs`.  E.g.:

```bash
sudo BROPATH="$PWD/bro" osqueryi
```

# TODO

 * [ ] Better Bro log path detection.
 * [ ] Add variable `BROLOGS` to specify where the bro logs are.
 * [ ] Better type handling?   

