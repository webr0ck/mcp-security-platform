# Demo assets

The headline, **no-full-stack** demo of this project is the verifiable network-isolation control —
it statically resolves the compose topology and proves backend MCP servers can't reach the proxy.

## Run it

```bash
make demo            # or: bash scripts/demo.sh
```

A captured transcript of the expected output is in [`isolation-demo.txt`](isolation-demo.txt).

## Regenerate the GIF (reproducible)

The GIF is generated from source with [`vhs`](https://github.com/charmbracelet/vhs) so it's
deterministic and reviewable in PRs (we commit the `.tape`, not a hand-recorded blob):

```bash
brew install vhs              # macOS; see vhs repo for other platforms
vhs docs/demo/isolation.tape  # writes docs/demo/isolation.gif
```

Then reference it from the README:

```markdown
![Network isolation demo](docs/demo/isolation.gif)
```

## A fuller demo (needs the lab)

To show the **zero-credential Claude Code** flow end to end, bring up the lab
(`make -f Makefile.lab lab-up`) and follow the README's *Connecting Claude Code* section. Record it
with the same `vhs` approach against a new tape file.
