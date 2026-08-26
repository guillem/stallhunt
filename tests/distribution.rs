//! Deterministic checks for MCP directory and plugin distribution metadata.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use serde_json::Value;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_json(path: &Path) -> Value {
    let text = fs::read_to_string(path).unwrap_or_else(|error| {
        panic!("failed to read {}: {error}", path.display());
    });
    serde_json::from_str(&text).unwrap_or_else(|error| {
        panic!("failed to parse {}: {error}", path.display());
    })
}

#[test]
fn openai_plugin_is_versioned_and_self_contained() {
    let plugin_root = root().join("plugins/stallhunt");
    let manifest = read_json(&plugin_root.join(".codex-plugin/plugin.json"));
    assert_eq!(manifest["name"], "stallhunt");
    assert_eq!(manifest["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(manifest["mcpServers"], "./.mcp.json");
    assert_eq!(
        manifest["interface"]["capabilities"],
        serde_json::json!(["Read"])
    );

    for field in ["privacyPolicyURL", "termsOfServiceURL", "websiteURL"] {
        assert!(
            manifest["interface"][field]
                .as_str()
                .is_some_and(|url| url.starts_with("https://")),
            "missing HTTPS {field}"
        );
    }
    for field in ["composerIcon", "logo"] {
        let relative = manifest["interface"][field]
            .as_str()
            .expect("asset path")
            .strip_prefix("./")
            .expect("asset path starts with ./");
        assert!(plugin_root.join(relative).is_file(), "missing {field}");
    }

    let mcp = read_json(&plugin_root.join(".mcp.json"));
    assert_eq!(mcp["mcpServers"]["stallhunt"]["command"], "stallhunt");
    assert_eq!(
        mcp["mcpServers"]["stallhunt"]["args"],
        serde_json::json!(["mcp"])
    );
}

#[test]
fn mcpb_manifest_is_linux_local_and_matches_the_package() {
    let manifest = read_json(&root().join("distribution/mcpb/manifest.json"));
    assert_eq!(manifest["manifest_version"], "0.3");
    assert_eq!(manifest["name"], "stallhunt");
    assert_eq!(manifest["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(manifest["server"]["type"], "binary");
    assert_eq!(manifest["server"]["entry_point"], "server/stallhunt");
    assert_eq!(
        manifest["server"]["mcp_config"]["args"],
        serde_json::json!(["mcp"])
    );
    assert_eq!(
        manifest["compatibility"]["platforms"],
        serde_json::json!(["linux"])
    );
    assert_eq!(manifest["tools"].as_array().map(Vec::len), Some(4));
    assert!(
        manifest["privacy_policies"][0]
            .as_str()
            .is_some_and(|url| url.starts_with("https://"))
    );
}

#[test]
fn registry_template_and_packaging_scripts_are_release_ready() {
    let template = fs::read_to_string(root().join("distribution/mcp-registry/server.json.in"))
        .expect("registry template");
    assert!(template.contains("io.github.guillem/stallhunt"));
    assert!(template.contains("@VERSION@"));
    assert!(template.contains("@SHA256@"));
    assert!(template.contains(".mcpb"));

    let rendered = template
        .replace("@VERSION@", env!("CARGO_PKG_VERSION"))
        .replace("@SHA256@", &"a".repeat(64));
    let value: Value = serde_json::from_str(&rendered).expect("rendered registry metadata");
    assert_eq!(value["packages"][0]["registryType"], "mcpb");
    assert_eq!(value["packages"][0]["transport"]["type"], "stdio");
    assert_eq!(value["packages"][0]["fileSha256"], "a".repeat(64));

    for script in [
        "tools/package-mcpb.sh",
        "tools/render-mcp-registry-metadata.sh",
    ] {
        let metadata = fs::metadata(root().join(script)).expect("script metadata");
        assert_ne!(
            metadata.permissions().mode() & 0o111,
            0,
            "{script} executable"
        );
    }
}
