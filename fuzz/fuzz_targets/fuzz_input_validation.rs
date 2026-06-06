// Copyright (c) 2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust (ABN 61 633 823 792)
// SPDX-License-Identifier: AGPL-3.0-only

#![no_main]

use libfuzzer_sys::fuzz_target;
use provii_verifier::security::validation::InputValidator;

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }

    // Convert fuzzer data to string
    let input_str = String::from_utf8_lossy(data).to_string();
    let validator = InputValidator::default();

    // Test 1: validate_string with various size limits
    for max_size in [10, 50, 100, 255, 1024, 10240].iter() {
        let _ = validator.validate_string(&input_str, "fuzz_field", *max_size);
    }

    // Test 2: validate_base64url with various decoded size limits
    for max_decoded in [8, 16, 32, 64, 128, 1024, 10240].iter() {
        let _ = validator.validate_base64url(&input_str, "fuzz_b64", *max_decoded);
    }

    // Test 3: validate_base64url_fixed with various expected sizes
    for expected_size in [8, 16, 32, 64].iter() {
        let _ = validator.validate_base64url_fixed(&input_str, "fuzz_b64_fixed", *expected_size);
    }

    // Test 4: validate_uuid
    let _ = validator.validate_uuid(&input_str, "fuzz_uuid");

    // Test 5: validate_origin
    let _ = validator.validate_origin(&input_str);

    // Test 6: validate_code_verifier
    let _ = validator.validate_code_verifier(&input_str);

    // Test 7: validate_code_challenge
    let _ = validator.validate_code_challenge(&input_str);

    // Test 8: sanitize_for_logging with various max lengths
    for max_len in [10, 50, 100, 1000].iter() {
        let _ = validator.sanitize_for_logging(&input_str, *max_len);
    }

    // Test 9: validate_request_size for different endpoints
    let size = data.len();
    let _ = validator.validate_request_size(size, "/v1/challenge");
    let _ = validator.validate_request_size(size, "/v1/verify");
    let _ = validator.validate_request_size(size, "/v1/challenge/*/redeem");
    let _ = validator.validate_request_size(size, "/v1/other");

    // Test 10: Test with embedded null bytes
    if !input_str.contains('\0') && data.len() > 2 {
        let with_null = format!("{}\0{}", &input_str[..input_str.len()/2], &input_str[input_str.len()/2..]);
        let _ = validator.validate_string(&with_null, "fuzz_null", 1024);
    }

    // Test 11: Test with various whitespace patterns
    let with_leading_ws = format!("  {}", input_str);
    let with_trailing_ws = format!("{}  ", input_str);
    let with_both_ws = format!("  {}  ", input_str);

    let _ = validator.validate_string(&with_leading_ws, "fuzz_ws1", 1024);
    let _ = validator.validate_string(&with_trailing_ws, "fuzz_ws2", 1024);
    let _ = validator.validate_string(&with_both_ws, "fuzz_ws3", 1024);

    // Test 12: Test origin with various schemes
    let schemes = ["https://", "http://", "javascript:", "data:", "vbscript:", "ftp://"];
    for scheme in schemes.iter() {
        let origin_test = format!("{}{}", scheme, input_str);
        let _ = validator.validate_origin(&origin_test);
    }

    // Test 13: Test origin with port numbers
    if input_str.len() > 5 {
        let with_port = format!("https://{}:8080", &input_str[..5]);
        let _ = validator.validate_origin(&with_port);
    }

    // Test 14: Test base64url with invalid characters
    let invalid_chars = ['+', '/', '=', '!', '@', '#', '$', '%'];
    for ch in invalid_chars.iter() {
        let with_invalid = format!("{}{}", input_str, ch);
        let _ = validator.validate_base64url(&with_invalid, "fuzz_invalid", 1024);
    }

    // Test 15: Test PKCE verifier with various lengths
    if input_str.len() >= 43 {
        let verifier_43 = &input_str[..43];
        let _ = validator.validate_code_verifier(verifier_43);
    }
    if input_str.len() >= 128 {
        let verifier_128 = &input_str[..128];
        let _ = validator.validate_code_verifier(verifier_128);
    }

    // Test 16: Test PKCE verifier with special characters
    if input_str.len() > 10 {
        let with_dash = format!("{}-", &input_str[..42.min(input_str.len())]);
        let with_dot = format!("{}.", &input_str[..42.min(input_str.len())]);
        let with_underscore = format!("{}~", &input_str[..42.min(input_str.len())]);

        let _ = validator.validate_code_verifier(&with_dash);
        let _ = validator.validate_code_verifier(&with_dot);
        let _ = validator.validate_code_verifier(&with_underscore);
    }

    // Test 17: Test UUID with various formats
    if data.len() >= 36 {
        // Try to construct UUID-like string
        let uuid_like = format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            data[0], data[1], data[2], data[3],
            data[4], data[5],
            data[6], data[7],
            data[8], data[9],
            data[10], data[11], data[12], data[13], data[14], data[15]
        );
        let _ = validator.validate_uuid(&uuid_like, "fuzz_uuid");
    }

    // Test 18: Test sanitize_for_logging with control characters
    let with_newline = format!("{}\n{}", &input_str, &input_str);
    let with_carriage = format!("{}\r{}", &input_str, &input_str);
    let with_tab = format!("{}\t{}", &input_str, &input_str);

    let _ = validator.sanitize_for_logging(&with_newline, 100);
    let _ = validator.sanitize_for_logging(&with_carriage, 100);
    let _ = validator.sanitize_for_logging(&with_tab, 100);

    // Test 19: Test very long inputs
    if data.len() > 10 {
        let repeated = input_str.repeat(100);
        let _ = validator.validate_string(&repeated, "fuzz_long", 1024);
        let _ = validator.validate_origin(&repeated);
        let _ = validator.sanitize_for_logging(&repeated, 50);
    }

    // Test 20: Test empty string
    let _ = validator.validate_string("", "fuzz_empty", 1024);
    let _ = validator.validate_base64url("", "fuzz_empty_b64", 1024);
    let _ = validator.sanitize_for_logging("", 100);

    // Test 21: Test single character
    if !input_str.is_empty() {
        let single = &input_str[..1];
        let _ = validator.validate_string(single, "fuzz_single", 10);
        let _ = validator.validate_origin(single);
    }

    // Test 22: Test with only whitespace
    let only_spaces = "     ";
    let only_tabs = "\t\t\t\t";
    let only_newlines = "\n\n\n\n";

    let _ = validator.validate_string(only_spaces, "fuzz_ws_only1", 100);
    let _ = validator.validate_string(only_tabs, "fuzz_ws_only2", 100);
    let _ = validator.validate_string(only_newlines, "fuzz_ws_only3", 100);

    // Test 23: Test case sensitivity
    if input_str.len() > 0 {
        let uppercase = input_str.to_uppercase();
        let lowercase = input_str.to_lowercase();

        let _ = validator.validate_string(&uppercase, "fuzz_upper", 1024);
        let _ = validator.validate_string(&lowercase, "fuzz_lower", 1024);
        let _ = validator.validate_base64url(&uppercase, "fuzz_b64_upper", 1024);
        let _ = validator.validate_base64url(&lowercase, "fuzz_b64_lower", 1024);
    }

    // Test 24: Test with Unicode
    let unicode_test = format!("{}🎉🔐💥", input_str);
    let _ = validator.validate_string(&unicode_test, "fuzz_unicode", 1024);
    let _ = validator.sanitize_for_logging(&unicode_test, 100);

    // Test 25: Test origin with multiple subdomains
    if input_str.len() > 5 {
        let subdomain = format!("https://a.b.c.{}.com", &input_str[..5]);
        let _ = validator.validate_origin(&subdomain);
    }
});
