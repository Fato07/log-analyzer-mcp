# Demo Generation

This directory contains assets for generating the project demo GIF.

## Prerequisites

Install VHS (Charmbracelet):

```bash
# macOS
brew install vhs

# Linux (Debian/Ubuntu)
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://repo.charm.sh/apt/gpg.key | sudo gpg --dearmor -o /etc/apt/keyrings/charm.gpg
echo "deb [signed-by=/etc/apt/keyrings/charm.gpg] https://repo.charm.sh/apt/ * *" | sudo tee /etc/apt/sources.list.d/charm.list
sudo apt update && sudo apt install vhs

# Or via Go
go install github.com/charmbracelet/vhs@latest
```

VHS requires `ttyd` and `ffmpeg` (installed automatically with Homebrew).

## Generate Demo

```bash
cd demo
vhs demo.tape
```

This will create `demo.gif` in the current directory.

## Optimize GIF Size (Optional)

```bash
# Install gifsicle
brew install gifsicle  # macOS
# or: sudo apt install gifsicle  # Linux

# Optimize
gifsicle -O3 --colors 128 demo.gif -o demo.gif
```

## Customization

Edit `demo.tape` to adjust:

- `Set Width/Height` - GIF dimensions
- `Set Theme` - Terminal color scheme ([available themes](https://github.com/charmbracelet/vhs?tab=readme-ov-file#set-theme))
- `Set FontSize` - Text size
- `Sleep` durations - Timing between steps
- `Set PlaybackSpeed` - Animation speed

## Files

| File | Purpose |
|------|---------|
| `demo.tape` | VHS recording script |
| `demo.gif` | Generated demo (after running VHS) |
| `README.md` | This file |

## CI/CD

The GitHub workflow `.github/workflows/demo.yml` automatically regenerates the GIF when demo-related files change.
