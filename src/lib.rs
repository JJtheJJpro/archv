#![no_std]

// Minimal panic handler for standard no_std bare-metal/embedded targets.
//#[panic_handler]
//fn panic(_info: &core::panic::PanicInfo) -> ! {
//    loop {}
//}

use core::fmt::Display;

#[derive(Debug)]
pub enum ArchInfo {
    X86_64 { level: &'static str },
    X86 { level: &'static str },
    AArch64 { version: &'static str },
    Arm32 { version: &'static str },
    Other(&'static str),
}
impl Display for ArchInfo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::X86_64 { level } => {
                write!(f, "{level}")
            }
            Self::X86 { level } => {
                write!(f, "{level}")
            }
            Self::AArch64 { version } => {
                write!(f, "{version}")
            }
            Self::Arm32 { version } => {
                write!(f, "{version}")
            }
            Self::Other(other) => {
                write!(f, "{other}")
            }
        }
    }
}

pub fn detect_arch_and_version() -> ArchInfo {
    if cfg!(target_arch = "x86_64") {
        ArchInfo::X86_64 {
            level: detect_x86_64_level(),
        }
    } else if cfg!(target_arch = "x86") {
        ArchInfo::X86 {
            level: detect_x86_level(),
        }
    } else if cfg!(target_arch = "aarch64") {
        ArchInfo::AArch64 {
            version: detect_aarch64_version(),
        }
    } else if cfg!(target_arch = "arm") {
        ArchInfo::Arm32 {
            version: detect_arm32_version(),
        }
    } else {
        ArchInfo::Other(get_target_arch_str())
    }
}

pub const fn get_target_arch_str() -> &'static str {
    if cfg!(target_arch = "x86_64") {
        "x86_64"
    } else if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else if cfg!(target_arch = "x86") {
        "x86"
    } else if cfg!(target_arch = "arm") {
        "arm"
    } else if cfg!(target_arch = "riscv64") {
        "riscv64"
    } else {
        "unknown"
    }
}

// ---------------------------------------------------------
// Bare-Metal / no_std x86_64 CPUID Microarchitecture Detection
// ---------------------------------------------------------
fn detect_x86_64_level() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    {
        use core::arch::x86_64::__cpuid;

        // Helper closures to test specific register bits
        // Leaf 1: ECX & EDX
        let cpuid1 = __cpuid(1);
        let ecx1 = cpuid1.ecx;
        //let edx1 = cpuid1.edx;

        // Leaf 7 (Sub-leaf 0): EBX, ECX, EDX
        let cpuid7 = __cpuid(7);
        let ebx7 = cpuid7.ebx;
        //let ecx7 = cpuid7.ecx;

        // Feature flags mapping
        let sse3 = (ecx1 & (1 << 0)) != 0;
        let ssse3 = (ecx1 & (1 << 9)) != 0;
        let fma = (ecx1 & (1 << 12)) != 0;
        let cmpxchg16b = (ecx1 & (1 << 13)) != 0;
        let sse4_1 = (ecx1 & (1 << 19)) != 0;
        let sse4_2 = (ecx1 & (1 << 20)) != 0;
        let movbe = (ecx1 & (1 << 22)) != 0;
        let popcnt = (ecx1 & (1 << 23)) != 0;
        let osxsave = (ecx1 & (1 << 27)) != 0;
        let avx = (ecx1 & (1 << 28)) != 0;
        let f16c = (ecx1 & (1 << 29)) != 0;

        let bmi1 = (ebx7 & (1 << 3)) != 0;
        let avx2 = (ebx7 & (1 << 5)) != 0;
        let bmi2 = (ebx7 & (1 << 8)) != 0;
        let avx512f = (ebx7 & (1 << 16)) != 0;
        let avx512dq = (ebx7 & (1 << 17)) != 0;
        let avx512cd = (ebx7 & (1 << 28)) != 0;
        let avx512bw = (ebx7 & (1 << 30)) != 0;
        let avx512vl = (ebx7 & (1 << 31)) != 0;

        // Verify OS support for AVX registers (XCR0) if OSXSAVE is enabled
        let mut avx_supported = avx && osxsave;
        if avx_supported {
            // Read XCR0 using xgetbv instruction
            let xcr0: u64;
            let eax: u32;
            let edx: u32;
            unsafe {
                core::arch::asm!(
                    "xgetbv",
                    in("ecx") 0,
                    out("eax") eax,
                    out("edx") edx,
                    options(nomem, nostack)
                );
                xcr0 = ((edx as u64) << 32) | (eax as u64);
            }
            // Bits 1 and 2 must be set for SSE and AVX state management
            avx_supported = (xcr0 & 0x6) == 0x6;
        }

        // x86-64-v4: AVX512 features
        let is_v4 = avx_supported && avx512f && avx512bw && avx512cd && avx512dq && avx512vl;

        if is_v4 {
            return "x86-64-v4";
        }

        // x86-64-v3: AVX/AVX2 + BMI1/BMI2 + FMA + F16C + MOVBE
        let is_v3 = avx_supported && avx2 && bmi1 && bmi2 && f16c && fma && movbe;

        if is_v3 {
            return "x86-64-v3";
        }

        // x86-64-v2: CMPXCHG16B + POPCNT + SSE3 + SSSE3 + SSE4.1 + SSE4.2
        let is_v2 = cmpxchg16b && popcnt && sse3 && ssse3 && sse4_1 && sse4_2;

        if is_v2 {
            return "x86-64-v2";
        }

        "x86-64-v1"
    }

    #[cfg(not(target_arch = "x86_64"))]
    "N/A"
}

// ---------------------------------------------------------
// x86 Detection Fallback
// ---------------------------------------------------------
fn detect_x86_level() -> &'static str {
    #[cfg(target_arch = "x86")]
    {
        use core::arch::x86::__cpuid;

        // CPUID leaf 1 gives the x86 family encoding. Intel family numbers map
        // cleanly to the historic i386/i486/i586/i686 progression.
        let cpuid1 = __cpuid(1);
        let eax = cpuid1.eax;
        let family = ((eax >> 8) & 0x0f) as u32;
        let extended_family = ((eax >> 20) & 0xff) as u32;

        match family {
            3 => "i386",
            4 => "i486",
            5 => "i586",
            6 => "i686",
            15 => "x86 (family 15 / Pentium 4 / later)",
            _ if extended_family > 0 => "x86 (extended family)",
            _ => "x86",
        }
    }

    #[cfg(not(target_arch = "x86"))]
    "N/A"
}

// ---------------------------------------------------------
// ARM32 Detection Fallback
// ---------------------------------------------------------
fn detect_arm32_version() -> &'static str {
    #[cfg(target_arch = "arm")]
    {
        "ARM32 (AArch32 / Armv7-A baseline)"
    }

    #[cfg(not(target_arch = "arm"))]
    "N/A"
}

// ---------------------------------------------------------
// AArch64 Detection Fallback
// ---------------------------------------------------------
fn detect_aarch64_version() -> &'static str {
    #[cfg(target_arch = "aarch64")]
    {
        // Without an OS (e.g. Linux hwcap or macOS sysctl), reading system registers
        // directly (like ID_AA64ISAR0_EL1) requires Kernel/EL1 privileges.
        // In bare-metal/EL0 user space, we safely report the baseline ISA target.
        "Armv8.0-A (Baseline / Unpivileged)"
    }

    #[cfg(not(target_arch = "aarch64"))]
    "N/A"
}
