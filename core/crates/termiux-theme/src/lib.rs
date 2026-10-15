//! Built-in colour themes and importers for iTerm2 (`.itermcolors`) and Ghostty theme files.

use termiux_model::{Theme, now};
use uuid::Uuid;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ThemeError {
    #[error("not an iTerm2 or Ghostty theme")]
    UnknownFormat,
    #[error("invalid theme: {0}")]
    Invalid(String),
}

/// Namespace for deterministic built-in theme ids, so they are stable across devices.
const BUILTIN_NAMESPACE: Uuid = Uuid::from_u128(0x7e6d_1a3c_9b2f_4c8e_a1d0_5f3b_2c9e_8a41);

struct Preset {
    name: &'static str,
    fg: &'static str,
    bg: &'static str,
    cursor: &'static str,
    selection: &'static str,
    palette: [&'static str; 16],
}

const PRESETS: &[Preset] = &[
    Preset {
        name: "Termiux Dark",
        fg: "#d7dae0",
        bg: "#15171c",
        cursor: "#6fa8ff",
        selection: "#2c3240",
        palette: [
            "#1f2229", "#f0717e", "#8fd18a", "#e8c272", "#6fa8ff", "#c792ea", "#5fd4d4", "#c8ccd4", "#4b5263",
            "#ff8a95", "#a8e6a3", "#f5d58e", "#8cbcff", "#d7a8f5", "#7fe5e5", "#f2f4f8",
        ],
    },
    Preset {
        name: "Termiux Light",
        fg: "#383a42",
        bg: "#fafafa",
        cursor: "#526fff",
        selection: "#e5e5e6",
        palette: [
            "#383a42", "#e45649", "#50a14f", "#c18401", "#4078f2", "#a626a4", "#0184bc", "#a0a1a7", "#696c77",
            "#e45649", "#50a14f", "#c18401", "#4078f2", "#a626a4", "#0184bc", "#fafafa",
        ],
    },
    Preset {
        name: "Solarized Dark",
        fg: "#839496",
        bg: "#002b36",
        cursor: "#93a1a1",
        selection: "#073642",
        palette: [
            "#073642", "#dc322f", "#859900", "#b58900", "#268bd2", "#d33682", "#2aa198", "#eee8d5", "#002b36",
            "#cb4b16", "#586e75", "#657b83", "#839496", "#6c71c4", "#93a1a1", "#fdf6e3",
        ],
    },
    Preset {
        name: "Solarized Light",
        fg: "#657b83",
        bg: "#fdf6e3",
        cursor: "#586e75",
        selection: "#eee8d5",
        palette: [
            "#073642", "#dc322f", "#859900", "#b58900", "#268bd2", "#d33682", "#2aa198", "#eee8d5", "#002b36",
            "#cb4b16", "#586e75", "#657b83", "#839496", "#6c71c4", "#93a1a1", "#fdf6e3",
        ],
    },
    Preset {
        name: "Dracula",
        fg: "#f8f8f2",
        bg: "#282a36",
        cursor: "#f8f8f2",
        selection: "#44475a",
        palette: [
            "#21222c", "#ff5555", "#50fa7b", "#f1fa8c", "#bd93f9", "#ff79c6", "#8be9fd", "#f8f8f2", "#6272a4",
            "#ff6e6e", "#69ff94", "#ffffa5", "#d6acff", "#ff92df", "#a4ffff", "#ffffff",
        ],
    },
    Preset {
        name: "Nord",
        fg: "#d8dee9",
        bg: "#2e3440",
        cursor: "#d8dee9",
        selection: "#434c5e",
        palette: [
            "#3b4252", "#bf616a", "#a3be8c", "#ebcb8b", "#81a1c1", "#b48ead", "#88c0d0", "#e5e9f0", "#4c566a",
            "#bf616a", "#a3be8c", "#ebcb8b", "#81a1c1", "#b48ead", "#8fbcbb", "#eceff4",
        ],
    },
    Preset {
        name: "Gruvbox Dark",
        fg: "#ebdbb2",
        bg: "#282828",
        cursor: "#ebdbb2",
        selection: "#504945",
        palette: [
            "#282828", "#cc241d", "#98971a", "#d79921", "#458588", "#b16286", "#689d6a", "#a89984", "#928374",
            "#fb4934", "#b8bb26", "#fabd2f", "#83a598", "#d3869b", "#8ec07c", "#ebdbb2",
        ],
    },
    Preset {
        name: "One Dark",
        fg: "#abb2bf",
        bg: "#282c34",
        cursor: "#528bff",
        selection: "#3e4451",
        palette: [
            "#282c34", "#e06c75", "#98c379", "#e5c07b", "#61afef", "#c678dd", "#56b6c2", "#abb2bf", "#5c6370",
            "#e06c75", "#98c379", "#e5c07b", "#61afef", "#c678dd", "#56b6c2", "#ffffff",
        ],
    },
    Preset {
        name: "Tokyo Night",
        fg: "#c0caf5",
        bg: "#1a1b26",
        cursor: "#c0caf5",
        selection: "#33467c",
        palette: [
            "#15161e", "#f7768e", "#9ece6a", "#e0af68", "#7aa2f7", "#bb9af7", "#7dcfff", "#a9b1d6", "#414868",
            "#f7768e", "#9ece6a", "#e0af68", "#7aa2f7", "#bb9af7", "#7dcfff", "#c0caf5",
        ],
    },
    Preset {
        name: "Catppuccin Mocha",
        fg: "#cdd6f4",
        bg: "#1e1e2e",
        cursor: "#f5e0dc",
        selection: "#585b70",
        palette: [
            "#45475a", "#f38ba8", "#a6e3a1", "#f9e2af", "#89b4fa", "#f5c2e7", "#94e2d5", "#bac2de", "#585b70",
            "#f38ba8", "#a6e3a1", "#f9e2af", "#89b4fa", "#f5c2e7", "#94e2d5", "#a6adc8",
        ],
    },
];

pub fn builtin_id(name: &str) -> Uuid {
    Uuid::new_v5(&BUILTIN_NAMESPACE, name.as_bytes())
}

/// The default theme for new installs.
pub fn default_theme_id() -> Uuid {
    builtin_id(PRESETS[0].name)
}

pub fn builtin_themes() -> Vec<Theme> {
    PRESETS
        .iter()
        .map(|p| Theme {
            id: builtin_id(p.name),
            name: p.name.to_string(),
            foreground: p.fg.to_string(),
            background: p.bg.to_string(),
            cursor: p.cursor.to_string(),
            cursor_text: None,
            selection_background: p.selection.to_string(),
            selection_foreground: None,
            palette: p.palette.iter().map(|c| c.to_string()).collect(),
            builtin: true,
            updated_at: 0,
        })
        .collect()
}

/// Imports a theme file, detecting the format. `name` is used when the file has none.
pub fn import(name: &str, contents: &[u8]) -> Result<Theme, ThemeError> {
    let text = std::str::from_utf8(contents).unwrap_or_default();
    if text.trim_start().starts_with("<?xml") || text.contains("<plist") || contents.starts_with(b"bplist") {
        parse_itermcolors(name, contents)
    } else if text.lines().any(|l| l.trim_start().starts_with("palette")) {
        parse_ghostty(name, text)
    } else {
        Err(ThemeError::UnknownFormat)
    }
}

fn new_theme(name: &str) -> Theme {
    Theme {
        id: Uuid::new_v4(),
        name: name.to_string(),
        foreground: String::new(),
        background: String::new(),
        cursor: String::new(),
        cursor_text: None,
        selection_background: String::new(),
        selection_foreground: None,
        palette: vec![String::new(); 16],
        builtin: false,
        updated_at: now(),
    }
}

/// Fills unset colours from sensible fallbacks and checks everything is set.
fn finish(mut theme: Theme) -> Result<Theme, ThemeError> {
    if theme.foreground.is_empty() || theme.background.is_empty() {
        return Err(ThemeError::Invalid("missing foreground or background".into()));
    }
    if let Some(i) = theme.palette.iter().position(String::is_empty) {
        return Err(ThemeError::Invalid(format!("missing palette colour {i}")));
    }
    if theme.cursor.is_empty() {
        theme.cursor = theme.foreground.clone();
    }
    if theme.selection_background.is_empty() {
        theme.selection_background = theme.palette[8].clone();
    }
    Ok(theme)
}

/// `#rrggbb` from "#rgb", "#rrggbb" or "rrggbb".
pub fn normalize_hex(value: &str) -> Option<String> {
    let hex = value.trim().trim_start_matches('#');
    let hex = match hex.len() {
        3 => hex.chars().flat_map(|c| [c, c]).collect(),
        6 => hex.to_string(),
        _ => return None,
    };
    hex.chars().all(|c| c.is_ascii_hexdigit()).then(|| format!("#{}", hex.to_ascii_lowercase()))
}

/// Ghostty theme file: `key = value` lines, `palette = N=#rrggbb`.
pub fn parse_ghostty(name: &str, text: &str) -> Result<Theme, ThemeError> {
    let mut theme = new_theme(name);
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else { continue };
        let (key, value) = (key.trim(), value.trim());
        if key == "palette" {
            let (index, color) = value.split_once('=').ok_or_else(|| ThemeError::Invalid(line.into()))?;
            let index: usize = index.trim().parse().map_err(|_| ThemeError::Invalid(line.into()))?;
            let color = normalize_hex(color).ok_or_else(|| ThemeError::Invalid(line.into()))?;
            if index < 16 {
                theme.palette[index] = color;
            }
            continue;
        }
        let Some(color) = normalize_hex(value) else { continue };
        match key {
            "foreground" => theme.foreground = color,
            "background" => theme.background = color,
            "cursor-color" => theme.cursor = color,
            "cursor-text" => theme.cursor_text = Some(color),
            "selection-background" => theme.selection_background = color,
            "selection-foreground" => theme.selection_foreground = Some(color),
            _ => {}
        }
    }
    finish(theme)
}

/// iTerm2 `.itermcolors` property list (XML or binary).
pub fn parse_itermcolors(name: &str, contents: &[u8]) -> Result<Theme, ThemeError> {
    let value =
        plist::Value::from_reader(std::io::Cursor::new(contents)).map_err(|e| ThemeError::Invalid(e.to_string()))?;
    let dict = value.as_dictionary().ok_or(ThemeError::UnknownFormat)?;
    let color = |key: &str| -> Option<String> {
        let c = dict.get(key)?.as_dictionary()?;
        let component = |k: &str| c.get(k).and_then(|v| v.as_real()).map(|v| (v.clamp(0.0, 1.0) * 255.0).round() as u8);
        Some(format!(
            "#{:02x}{:02x}{:02x}",
            component("Red Component")?,
            component("Green Component")?,
            component("Blue Component")?
        ))
    };

    let mut theme = new_theme(name);
    for i in 0..16 {
        theme.palette[i] = color(&format!("Ansi {i} Color")).unwrap_or_default();
    }
    theme.foreground = color("Foreground Color").unwrap_or_default();
    theme.background = color("Background Color").unwrap_or_default();
    theme.cursor = color("Cursor Color").unwrap_or_default();
    theme.cursor_text = color("Cursor Text Color");
    theme.selection_background = color("Selection Color").unwrap_or_default();
    theme.selection_foreground = color("Selected Text Color");
    finish(theme)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtins_are_complete_and_stable() {
        let themes = builtin_themes();
        assert_eq!(themes[0].id, default_theme_id());
        for t in &themes {
            assert_eq!(t.palette.len(), 16, "{}", t.name);
            for c in t.palette.iter().chain([&t.foreground, &t.background, &t.cursor, &t.selection_background]) {
                assert_eq!(normalize_hex(c).as_deref(), Some(c.as_str()), "{}: {c}", t.name);
            }
        }
        assert_eq!(builtin_id("Dracula"), builtin_themes()[4].id);
    }

    #[test]
    fn hex_normalization() {
        assert_eq!(normalize_hex("FFF").as_deref(), Some("#ffffff"));
        assert_eq!(normalize_hex("#1A2b3C").as_deref(), Some("#1a2b3c"));
        assert_eq!(normalize_hex("#12345"), None);
        assert_eq!(normalize_hex("zzzzzz"), None);
    }

    const GHOSTTY: &str = "\
# Example theme
palette = 0=#000000
palette = 1=#cd3131
palette = 2=#0dbc79
palette = 3=#e5e510
palette = 4=#2472c8
palette = 5=#bc3fbc
palette = 6=#11a8cd
palette = 7=#e5e5e5
palette = 8=#666666
palette = 9=#f14c4c
palette = 10=#23d18b
palette = 11=#f5f543
palette = 12=#3b8eea
palette = 13=#d670d6
palette = 14=#29b8db
palette = 15=#ffffff
background = 1e1e1e
foreground = #cccccc
cursor-color = #aeafad
selection-background = #264f78
selection-foreground = #ffffff
";

    #[test]
    fn ghostty_theme() {
        let t = import("VS Dark", GHOSTTY.as_bytes()).unwrap();
        assert_eq!(t.name, "VS Dark");
        assert_eq!(t.background, "#1e1e1e");
        assert_eq!(t.foreground, "#cccccc");
        assert_eq!(t.palette[9], "#f14c4c");
        assert_eq!(t.selection_foreground.as_deref(), Some("#ffffff"));
        assert!(!t.builtin);
    }

    #[test]
    fn ghostty_missing_palette_is_rejected() {
        let partial = GHOSTTY.replace("palette = 7=#e5e5e5\n", "");
        assert_eq!(import("x", partial.as_bytes()), Err(ThemeError::Invalid("missing palette colour 7".into())));
    }

    fn itermcolors() -> String {
        let entry = |key: &str, r: f64, g: f64, b: f64| {
            format!(
                "<key>{key}</key><dict><key>Blue Component</key><real>{b}</real>\
                 <key>Green Component</key><real>{g}</real><key>Red Component</key><real>{r}</real></dict>"
            )
        };
        let mut body = String::new();
        for i in 0..16 {
            body += &entry(&format!("Ansi {i} Color"), i as f64 / 15.0, 0.0, 1.0);
        }
        body += &entry("Background Color", 0.0, 0.0, 0.0);
        body += &entry("Foreground Color", 1.0, 1.0, 1.0);
        body += &entry("Selection Color", 0.2, 0.2, 0.2);
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
             \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict>{body}</dict></plist>"
        )
    }

    #[test]
    fn iterm_theme() {
        let t = import("Blues", itermcolors().as_bytes()).unwrap();
        assert_eq!(t.background, "#000000");
        assert_eq!(t.foreground, "#ffffff");
        assert_eq!(t.palette[0], "#0000ff");
        assert_eq!(t.palette[15], "#ff00ff");
        assert_eq!(t.selection_background, "#333333");
        // No cursor colour in the file: falls back to the foreground.
        assert_eq!(t.cursor, "#ffffff");
    }

    #[test]
    fn unknown_format() {
        assert_eq!(import("x", b"hello world"), Err(ThemeError::UnknownFormat));
    }
}
