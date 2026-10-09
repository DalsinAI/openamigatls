# Third-party notices

## BearSSL 0.6 (third_party/bearssl)

OpenTLS's TLS engine. MIT licence, Copyright (c) 2016 Thomas Pornin; the
full text is in `third_party/bearssl/LICENSE.txt` and below.

- Source: https://bearssl.org/bearssl-0.6.tar.gz (released 14 August 2018),
  765,094 bytes, SHA-256
  `6705bba1714961b41a728dfc5debbe348d2966c117649392f8c8139efc83ff14`.
  BearSSL publishes no signature or hash for it; the tarball is not in git.
- Imported: `inc/`, `LICENSE.txt`, `README.txt`, and the 108 files of `src/`
  a TLS client needs (the server side, private-key code and modes OpenTLS
  does not offer left out), with the T0 sources of the generated
  handshake and X.509 code (`*.t0`). Not imported: `T0Comp.exe` (a binary),
  tools, samples and tests.
- Changed: nothing. OpenTLS's build sets BearSSL's own configuration macros
  (`build-amiga-tls.sh`) and plugs OpenCrypto in through BearSSL's public
  function tables (`src/opentls/ot_glue.c`).

```
Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## The CA bundle (not in this repository)

The trust store OpenTLS reads (`ENVARC:OpenTLS/ca-bundle.pem`) is meant to
carry Mozilla's CA list, which is under the Mozilla Public License 2.0
(file-level copyleft: the bundle ships as its own file, with its licence
and source named, beside MIT-licensed OpenTLS). Which bundle an install
carries, and where it comes from, is not settled by this repository.
