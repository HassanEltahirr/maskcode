# Third-party notices

Reviewed on 2026-09-12; protocol-reference notice updated on 2026-09-13. These
notices describe third-party components and design references used by MaskCode.
MaskCode's original source code is licensed separately under the MIT license in
[LICENSE](LICENSE). Third-party components retain their respective licenses;
these notices grant no rights to provider services, accounts, or trademarks.

MaskCode declares the pinned runtime dependencies `prompt_toolkit==3.0.52` and
`wcwidth==0.7.0`; wcwidth is also a dependency of prompt_toolkit. The versions
inspected below match those pins. Recheck notices before changing dependencies.
Dependencies are installed separately and are not vendored
into MaskCode's Python package. Keep their own license files when distributing
them together with MaskCode. Python and setuptools are externally installed
runtime/build tools and are not bundled in this repository.

Version 0.7.0 also invokes separately installed Ollama, Claude Code, and Codex
executables. It reuses existing local Ollama model files (default detector:
`qwen2.5:1.5b`). No provider executable, Ollama source/binary, or model weight is
bundled or copied into MaskCode's distribution. Their respective licenses and
service terms apply independently; review exact artifacts before redistributing
any of these components.

MaskCode's terminal interface takes inspiration from the open-source Hermes
Agent terminal: its warm amber palette, welcome panel, persistent composer,
slash-command completion, multiline input, and compact status display.
MaskCode's interface code is independently implemented for its local privacy
gateway and Claude Code backend. MaskCode is not a complete Hermes fork, and
does not bundle Hermes source modules, its agent runtime, integrations, wordmark,
caduceus, or logo assets. It is not an official Nous Research product.

## Hermes Agent — design reference, MIT

Copyright (c) 2025 Nous Research.

References inspected on 2026-09-12, at the upstream `main` reference:

- Repository: <https://github.com/NousResearch/hermes-agent>
- Welcome panel: <https://github.com/NousResearch/hermes-agent/blob/main/hermes_cli/banner.py>
- Input and layout: <https://github.com/NousResearch/hermes-agent/blob/main/hermes_cli/cli_tui_mixin.py>
- Dependency versions: <https://github.com/NousResearch/hermes-agent/blob/main/pyproject.toml>
- Interface guide: <https://hermes-agent.nousresearch.com/docs/user-guide/cli/>
- License: <https://github.com/NousResearch/hermes-agent/blob/main/LICENSE>

The upstream reference is recorded as `main`; no immutable commit is claimed.
The upstream license is retained here as an acknowledgement of the design
reference. It does not pre-approve future changes or the use of trademarks.

```text
MIT License

Copyright (c) 2025 Nous Research

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Claude Agent SDK for Python — protocol reference, MIT

The stream-json control protocol in `privacy_gateway/engine.py` was implemented
with the SDK's query/client implementation as a protocol reference. The SDK
package and its bundled Claude Code executable are not vendored into MaskCode.
The upstream copyright and license are retained below.

Inspected on 2026-09-13 at the upstream `main` reference; no immutable commit is
claimed:

- Protocol reference: <https://github.com/anthropics/claude-agent-sdk-python/blob/main/src/claude_agent_sdk/_internal/query.py>
- License: <https://raw.githubusercontent.com/anthropics/claude-agent-sdk-python/main/LICENSE>

```text
MIT License

Copyright (c) 2025 Anthropic, PBC

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## prompt_toolkit 3.0.52 — BSD-3-Clause

The terminal UI uses prompt_toolkit for input editing, completion, and rendering.
License verified against version 3.0.52:
<https://github.com/prompt-toolkit/python-prompt-toolkit/blob/3.0.52/LICENSE>.
The `{organization}` placeholder is part of the upstream notice and is preserved
verbatim.

```text
Copyright (c) 2014, Jonathan Slenders
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice, this
  list of conditions and the following disclaimer in the documentation and/or
  other materials provided with the distribution.

* Neither the name of the {organization} nor the names of its
  contributors may be used to endorse or promote products derived from
  this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```
## wcwidth 0.7.0 — MIT and included Markus Kuhn notice

Transitive dependency of prompt_toolkit, used to measure displayed terminal
character widths. The complete notice below comes from the installed 0.7.0
release and was checked against its
[upstream license](https://github.com/jquast/wcwidth/blob/0.7.0/LICENSE).

```text
The MIT License (MIT)

Copyright (c) 2014 Jeff Quast <contact@jeffquast.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

Markus Kuhn -- 2007-05-26 (Unicode 5.0)

Permission to use, copy, modify, and distribute this software
for any purpose and without fee is hereby granted. The author
disclaims all warranties with regard to this software.
```

## Unicode data used by wcwidth — Unicode License V3

wcwidth 0.7.0 contains generated Unicode 17.0.0 tables, including data derived
from [EastAsianWidth.txt](https://www.unicode.org/Public/17.0.0/ucd/EastAsianWidth.txt).
These tables belong to the separately installed dependency. The source data's
notice identifies Copyright © 2025 Unicode®, Inc. and directs users to Unicode's
terms. The current [Unicode license](https://www.unicode.org/license.txt), inspected
on the review date above, is reproduced here as an additional upstream data notice.

```text
UNICODE LICENSE V3

COPYRIGHT AND PERMISSION NOTICE

Copyright © 1991-2026 Unicode, Inc.

NOTICE TO USER: Carefully read the following legal agreement. BY
DOWNLOADING, INSTALLING, COPYING OR OTHERWISE USING DATA FILES, AND/OR
SOFTWARE, YOU UNEQUIVOCALLY ACCEPT, AND AGREE TO BE BOUND BY, ALL OF THE
TERMS AND CONDITIONS OF THIS AGREEMENT. IF YOU DO NOT AGREE, DO NOT
DOWNLOAD, INSTALL, COPY, DISTRIBUTE OR USE THE DATA FILES OR SOFTWARE.
Permission is hereby granted, free of charge, to any person obtaining a
copy of data files and any associated documentation (the "Data Files") or
software and any associated documentation (the "Software") to deal in the
Data Files or Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, and/or sell
copies of the Data Files or Software, and to permit persons to whom the
Data Files or Software are furnished to do so, provided that either (a)
this copyright and permission notice appear with all copies of the Data
Files or Software, or (b) this copyright and permission notice appear in
associated Documentation.
THE DATA FILES AND SOFTWARE ARE PROVIDED "AS IS", WITHOUT WARRANTY OF ANY
KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT OF
THIRD PARTY RIGHTS.
IN NO EVENT SHALL THE COPYRIGHT HOLDER OR HOLDERS INCLUDED IN THIS NOTICE
BE LIABLE FOR ANY CLAIM, OR ANY SPECIAL INDIRECT OR CONSEQUENTIAL DAMAGES,
OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THE DATA
FILES OR SOFTWARE.
Except as contained in this notice, the name of a copyright holder shall
not be used in advertising or otherwise to promote the sale, use or other
dealings in these Data Files or Software without prior written
authorization of the copyright holder.
```

## Provider software and names

Claude Code is separately installed provider software; MaskCode does not bundle,
patch, rename, or relicense its executable. Provider software and services remain
subject to their own licenses, terms, and authorized authentication methods.
Names such as Claude, Claude Code, Anthropic, OpenAI, Hermes Agent, and Nous
Research identify the relevant third parties or compatibility references. Their
appearance does not imply sponsorship, partnership, approval, or endorsement.
MaskCode is an independent project and makes no claim to those names or logos.
These acknowledgements likewise do not imply endorsement by prompt_toolkit,
wcwidth, Unicode, or their contributors.
