use capstone::prelude::*;
use capstone::arch;
use goblin::mach::{Mach, MachO};
use std::path::PathBuf;

fn find_random_strings_that_give_us_internal_studio(
    pe: &MachO,
    input: &[u8],
    target: &[u8],
) -> Option<u64> {
    for seg in &pe.segments {
        if seg.name().unwrap_or_default() != "__TEXT" {
            continue;
        }
        let secs = seg.sections().ok()?;
        for (sect, _) in secs {
            if sect.segname().unwrap_or_default() == "__TEXT"
                && std::str::from_utf8(&sect.sectname)
                    .unwrap_or_default()
                    .trim_end_matches('\0')
                    == "__cstring"
            {
                let start = sect.offset as usize;
                let size = sect.size as usize;
                if let Some(off) = input[start..start + size]
                    .windows(target.len())
                    .position(|w| w == target)
                {
                    return Some(sect.addr + off as u64);
                }
            }
        }
    }
    None
}

fn insn_resolves_to(insns: &capstone::Instructions, idx: usize) -> Vec<u64> {
    let mut resolved_addrs = Vec::new();
    let insn = if let Some(i) = insns.get(idx) { i } else { return resolved_addrs; };
    
    let parse_hex = |s: &str| -> Vec<u64> {
        s.split("0x").flat_map(|p| p.split("0X")).skip(1).filter_map(|chunk| {
            let hex_part = chunk.chars().take_while(|c| c.is_ascii_hexdigit()).collect::<String>();
            if hex_part.is_empty() { None } else { u64::from_str_radix(&hex_part, 16).ok() }
        }).collect()
    };
    
    let op_str = insn.op_str().unwrap_or("");
    resolved_addrs.extend(parse_hex(op_str));

    if insn.mnemonic().unwrap_or("") == "adrp" {
        if let (Some(dest_reg), Some(&page_base)) = (
            op_str.split(',').next().map(|s| s.trim()),
            resolved_addrs.first()
        ) {
            for j in (idx + 1)..std::cmp::min(insns.len(), idx + 8) {
                let next_insn = insns.get(j).unwrap();
                let next_mnem = next_insn.mnemonic().unwrap_or("");
                let next_op_str = next_insn.op_str().unwrap_or("");
                let is_add = next_mnem.starts_with("add");
                let is_load = next_mnem.starts_with("ldr");

                if (is_add || is_load) && next_op_str.contains(dest_reg) {
                     if let Some(offset) = parse_hex(next_op_str).first() {
                         resolved_addrs.push(page_base + offset);
                     }
                }
            }
        }
    }

    resolved_addrs
}

// rushed, TODO: clean up later
pub fn start(input: &mut Vec<u8>, _output: &PathBuf) {
    let macho = match Mach::parse(&input).unwrap() {
        Mach::Binary(m) => m,
        _ => panic!("Error: Could not parse Roblox binary. Please report to https://github.com/7ap/internal-studio-patcher/issues"),
    };

    let voicechat_addr = find_random_strings_that_give_us_internal_studio(
        &macho,
        &input,
        b"VoiceChatEnableApiSecurityCheck",
    )
    .expect("Error: Could not find the first string that is searched for to get internal studio. Please report to https://github.com/7ap/internal-studio-patcher/issues");

    let start_api_addr = find_random_strings_that_give_us_internal_studio(
        &macho,
        &input,
        b"Start API Dump",
    )
    .expect("Error: Could not find the second string that is searched for to get internal studio. Please report to https://github.com/7ap/internal-studio-patcher/issues");

    let (text_o, text_s, text_b) = macho.segments.iter()
        .filter_map(|seg| {
            if seg.name().unwrap_or_default() == "__TEXT" {
                seg.sections().ok()?.into_iter().find_map(|(sect, _)| {
                    let name = std::str::from_utf8(&sect.sectname).unwrap_or_default().trim_end_matches('\0').to_string();
                    if sect.segname().unwrap_or_default() == "__TEXT" && name == "__text" {
                        Some((sect.offset as usize, sect.size as usize, sect.addr))
                    } else { None }
                })
            } else { None }
        })
        .next()
        .expect("text missing (this error isnt formatted because this literally should never happen)");

    let text_bytes = &input[text_o..text_o + text_s];

    let cs = Capstone::new()
        .arm64()
        .mode(arch::arm64::ArchMode::Arm)
        .detail(false)
        .build()
        .expect("failed to initialize capstone (this error isnt formatted because this literally should never happen)");

    const CHUNK_SIZE: usize = 64 * 1024;
    const OVERLAP: usize = 4 * 1024;

    let mut found_start = false;
    let mut found_voice = false;
    let mut start_ip: u64 = 0;
    let mut off: usize = 0;
    while off < text_bytes.len() && !(found_start && found_voice) {
        let end = std::cmp::min(text_bytes.len(), off + CHUNK_SIZE);
        let chunk = &text_bytes[off..end];
        let chunk_addr = text_b + off as u64;

        let insns = cs.disasm_all(chunk, chunk_addr).expect("disasm failed (this error isnt formatted because this literally should never happen)");

        for i in 0..insns.len() {
            if found_start && found_voice { break; }
            
            let resolved = insn_resolves_to(&insns, i);

            if !found_start && resolved.contains(&start_api_addr) {
                start_ip = insns.get(i).unwrap().address();
                found_start = true;
            }
            if !found_voice && resolved.contains(&voicechat_addr) {
                found_voice = true;
            }
        }

        if end == text_bytes.len() { break; }
        off = if end <= OVERLAP { end } else { end - OVERLAP };
    }

    if !found_start {
        panic!("Error: Could not find Start API Dump reference. Please report to https://github.com/7ap/internal-studio-patcher/issues");
    }
    if !found_voice {
        panic!("Error: Could not find voicechat reference anywhere. Please report to https://github.com/7ap/internal-studio-patcher/issues");
    }
    
    let scan_start_ip = if start_ip > text_b + 0x8000 { start_ip - 0x8000 } else { text_b };
    let scan_start_off = text_o + (scan_start_ip - text_b) as usize;
    let scan_len = (start_ip - scan_start_ip) as usize + 0x100;
    let scan_slice = &input[scan_start_off..scan_start_off + scan_len];
    let scan_insns = cs.disasm_all(scan_slice, scan_start_ip).expect("disasm2 failed (this error isnt formatted because this literally should never happen)");

    let mut func_start_ip: Option<u64> = None;
    for i in 0..scan_insns.len() {
        let ins = scan_insns.get(i).unwrap();
        if ins.address() >= start_ip { break; }
        let m = ins.mnemonic().unwrap_or("");
        let op = ins.op_str().unwrap_or("");
        if m == "stp" && op.contains("x29") && op.contains("x30") {
            func_start_ip = Some(ins.address());
        }
    }
    let func_start_ip = func_start_ip.expect("could not find function start (this error isnt formatted because this literally should never happen)");
    let func_bytes_off = text_o + (func_start_ip - text_b) as usize;
    let func_len = (start_ip - func_start_ip) as usize + 0x400;
    let func_slice = &input[func_bytes_off..func_bytes_off + func_len];
    let func_insns = cs.disasm_all(func_slice, func_start_ip).unwrap();

    let mut thinger_idx_in_func: Option<usize> = None;
    for i in 0..func_insns.len() {
        if insn_resolves_to(&func_insns, i).contains(&voicechat_addr) {
            thinger_idx_in_func = Some(i);
            break;
        }
    }
    let thinger_idx_in_func = thinger_idx_in_func.unwrap();
    let mut bl_above_idx_opt: Option<usize> = None;
    for i in (0..=thinger_idx_in_func).rev() {
        let m = func_insns.get(i).unwrap().mnemonic().unwrap_or("").to_lowercase();
        if m == "bl" {
            bl_above_idx_opt = Some(i);
            break;
        }
    }

    let identifier_addr = if let Some(bl_idx) = bl_above_idx_opt {
        insn_resolves_to(&func_insns, bl_idx).first().copied()
            .unwrap()
    } else {
        panic!("Error: Could not find identifier function. Please report to https://github.com/7ap/internal-studio-patcher/issues");
    };

    let mut found_cbz_addr: Option<u64> = None;
    let mut off: usize = 0;
    #[derive(Clone)]
    struct PrevMeta { ip: u64, mnemonic: String }
    let mut prev_meta: Option<PrevMeta> = None;

    while off < text_bytes.len() && found_cbz_addr.is_none() {
        let end = std::cmp::min(text_bytes.len(), off + CHUNK_SIZE);
        let chunk = &text_bytes[off..end];
        let chunk_addr = text_b + off as u64;
        let insns = cs.disasm_all(chunk, chunk_addr).unwrap();

        for i in 0..insns.len() {
            let cur = insns.get(i).unwrap();
            let cur_mnem = cur.mnemonic().unwrap_or("").to_string();
            
            if cur_mnem.to_lowercase() == "bl" {
                if let Some(target) = insn_resolves_to(&insns, i).first() {
                    if *target == identifier_addr {
                        if i >= 1 {
                            let prev = insns.get(i - 1).unwrap();
                            let pm = prev.mnemonic().unwrap_or("").to_lowercase();
                            if pm == "cbz" || pm == "tbz" || pm == "cbnz" {
                                found_cbz_addr = Some(prev.address());
                                break;
                            }
                        } else if let Some(pm) = &prev_meta {
                            let pm_l = pm.mnemonic.to_lowercase();
                            if pm_l == "cbz" || pm_l == "tbz" || pm_l == "cbnz" {
                                found_cbz_addr = Some(pm.ip);
                                break;
                            }
                        }
                    }
                }
            }

            prev_meta = Some(PrevMeta {
                ip: cur.address(),
                mnemonic: cur_mnem,
            });
        }

        if end == text_bytes.len() { break; }
        off = if end <= OVERLAP { end } else { end - OVERLAP };
    }

    let patch_addr = found_cbz_addr.expect("Error: Could not find the address to patch (have you already patched studio?). Please report to https://github.com/7ap/internal-studio-patcher/issues");
    let raw_start = text_o;
    let text_start = text_b;
    let offset = raw_start + (patch_addr - text_start) as usize;
    if offset + 4 > input.len() {
        eprintln!("ooob (this error isnt formatted because this literally should never happen)");
        std::process::exit(1);
    }
    input[offset..offset+4].copy_from_slice(&[0x1F, 0x20, 0x03, 0xD5]);
    std::fs::write(_output, &input).unwrap();
}