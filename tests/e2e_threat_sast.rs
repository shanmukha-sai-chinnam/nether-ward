use nether_ward::sast::{export_sarif, scan_directory};
use nether_ward::threat::{
    analyze_payload, calculate_entropy, calculate_windowed_entropy,
    scan_directory as threat_scan_dir,
};
use std::fs;
use std::path::Path;

#[test]
fn test_e2e_sast_directory_scan_and_sarif_export() {
    let dataset_dir = Path::new("datasets/threat_samples");
    if !dataset_dir.exists() {
        return;
    }

    let report = scan_directory(dataset_dir).expect("Directory SAST scan must succeed");
    assert!(report.total_files_scanned >= 5);
    assert!(report.total_findings > 0);
    assert!(report.critical_count > 0);
    assert!(report.high_count > 0);

    // Verify presence of multi-vector vulnerability categories
    let rule_ids: Vec<String> = report.findings.iter().map(|f| f.rule_id.clone()).collect();
    assert!(rule_ids.iter().any(|id| id == "NW-SEC-001")); // Hardcoded AWS Token
    assert!(rule_ids.iter().any(|id| id.starts_with("NW-SYS"))); // Reverse Shell / System execution
    assert!(rule_ids
        .iter()
        .any(|id| id.starts_with("NW-CODE") || id.starts_with("NW-INJ"))); // RCE / SQLi

    // Test SARIF export complies with OASIS SARIF v2.1.0 standard
    let temp_sarif = std::env::temp_dir().join(format!("test_sast_{}.sarif", std::process::id()));
    export_sarif(&report, &temp_sarif).expect("SARIF export must succeed");

    let sarif_contents = fs::read_to_string(&temp_sarif).expect("Must read exported SARIF file");
    let sarif_json: serde_json::Value =
        serde_json::from_str(&sarif_contents).expect("SARIF must be valid JSON");

    assert_eq!(sarif_json["version"], "2.1.0");
    assert!(sarif_json["$schema"]
        .as_str()
        .unwrap()
        .contains("sarif-schema-2.1.0.json"));

    let driver = &sarif_json["runs"][0]["tool"]["driver"];
    assert_eq!(driver["name"], "Nether Ward");
    assert_eq!(driver["version"], "0.2.0");

    let rules = driver["rules"]
        .as_array()
        .expect("Rules should be an array");
    assert!(!rules.is_empty());

    let results = sarif_json["runs"][0]["results"]
        .as_array()
        .expect("Results should be an array");
    assert!(!results.is_empty());

    let _ = fs::remove_file(&temp_sarif);
}

#[test]
fn test_e2e_windowed_entropy_stager_detection() {
    // Construct a simulated 4096-byte benign source file
    let mut benign_file = vec![b' '; 4096];
    for chunk in benign_file.chunks_mut(64) {
        let line = b"// Standard benign rust source code comment for testing entropy.\n";
        let len = line.len().min(chunk.len());
        chunk[..len].copy_from_slice(&line[..len]);
    }

    let global_ent_before = calculate_entropy(&benign_file);
    assert!(global_ent_before < 4.5);

    // Implant a high-entropy 256-byte simulated shellcode stager at aligned offset 2048
    let mut high_entropy_slice = [0u8; 256];
    for (i, byte) in high_entropy_slice.iter_mut().enumerate() {
        *byte = ((i * 137 + 89) % 256) as u8;
    }
    benign_file[2048..2304].copy_from_slice(&high_entropy_slice);

    let global_ent_after = calculate_entropy(&benign_file);
    // Overall file entropy remains relatively low because it's diluted by 4KB of benign text
    assert!(global_ent_after < 5.2);

    // Sliding-window entropy inspection must isolate and detect the stager
    let (max_window_ent, stager_offset) = calculate_windowed_entropy(&benign_file, 256, 64);
    assert!(
        max_window_ent >= 7.5,
        "Windowed entropy must catch embedded stager, got: {}",
        max_window_ent
    );
    assert!(stager_offset.is_some());
    assert_eq!(stager_offset.unwrap(), 2048);

    let report = analyze_payload(&benign_file);
    assert!(report.max_windowed_entropy >= 7.5);
    assert!(report
        .detected_indicators
        .iter()
        .any(|ind| ind.contains("Localized high entropy stager detected")));
}

#[test]
fn test_e2e_batch_threat_directory_triage() {
    let dataset_dir = Path::new("datasets/threat_samples");
    if !dataset_dir.exists() {
        return;
    }

    let batch = threat_scan_dir(dataset_dir).expect("Batch triage must succeed");
    assert!(batch.total_files >= 5);
    assert!(batch.total_bytes > 0);
    assert!(batch.critical_files > 0 || batch.high_files > 0);
}
