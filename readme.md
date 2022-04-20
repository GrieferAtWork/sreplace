# sreplace

StringREPLACE: a simple commandline utility for mass finding+replacing strings/words in text files.



### Building

sreplace can be built for both windows and unix system.

- Windows: Open `sreplace.sln` with Visual Studio and press `CTRL+SHIFT+B`

- Unix/GCC:

  ```sh
  gcc -o sreplace main.c
  ```

Known working target systems: `windows`, `cygwin`, `linux`, `KOS`

### Usage

The general idea behind `sreplace` is to specify FIND+REPLACE pairs, as well as a list of files/directories to search for FIND patterns that are then replaced. To prevent ambiguity, you should always invoke the utility as `sreplace -ibet -- FIND1 REPLACE1 FIND2 REPLACE2 -- file.txt`.

Flags:

- `-f`, `--find`: Instead of FIND+REPLACE pairs, all commandline strings are FIND, and rather than replace anything, print all matching locations as `file:line:col:nchars:pattern\n`
- `-i`, `--icase`: Ignore casing
- `-b`, `--bound`: Only match whole word (independently of`--regex`)
- `-r`, `--regex`: `FIND` patterns are regular expressions
	- NOTE: Currently only available on UNIX.
- `-e`, `--escape`: `FIND` and `REPLACE` undergo C-style control character expansion before being used
- `-t`, `--keep-mtime`: Preserve last-modified timestamps of modified files
- `-R`, `--recursive`: Accept directories in the list of files. Directories will be enumerated recursively, and all contained files are treated as if they were listed explicitly (but see `--ext=LIST`).
- `--ext=LIST`: Only scan files with extensions apart of `LIST` when they are encountered as the result of scanning a directory due to `-R` (example: `--ext=.txt:.c:.h` -- only find+replace `.txt`, `.c` and `.h` files)
- `-n N`, `--max=N`: Stop after N matches


### Examples

Here are some examples:

- Replace data in streams

  ```sh
  $ echo Hello Wrold | sreplace -- Wrold World
  Hello World
  ```

- Inplace-modify files

  ```sh
  $ echo foo bar foobar > file
  $ sreplace -b -- bar baz -- file
  $ cat file
  foo baz foobar
  ```

- Find occurances

  ```sh
  $ echo foo bar foobar > file
  $ echo bar foo foobar >> file
  $ sreplace -fb -- foo bar -- file
  file:1:1:3:foo
  file:1:5:3:bar
  file:2:1:3:bar
  file:2:5:3:foo
  ```

- Replace non-printable characters (including `\0` NUL)

  ```sh
  $ echo -e 'a\0b\0c\0d\0e' | sreplace -e -- '\0' '_'
  a_b_c_d_e
  ```

- Count occurances

  ```sh
  $ sreplace -fb -- opt_progname -- main.c | wc -l
  4
  ```

