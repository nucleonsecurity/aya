use aya::{
    Btf, Ebpf,
    programs::{FModRet, ProgramError, ProgramType, TestRun as _},
    sys::is_program_supported,
    util::KernelVersion,
};
use aya_obj::btf::BtfError;

const MODIFY_RETURN_TARGET: &str = "bpf_modify_return_test";

// The tracing test-run handler packs its result as `(side_effect << 16) | ret`,
// where `side_effect` counts how many times the target's `*b += 1` was observed.
// https://github.com/torvalds/linux/blob/v7.1-rc4/net/bpf/test_run.c#L716-L732
fn side_effect_count(retval: u32) -> u32 {
    retval >> 16
}

// An fmod_ret program returning non-zero replaces the target's return value and
// short-circuits it, suppressing the `*b += 1` side effect. A program returning
// zero lets the target run. The difference in observed side effects proves the
// return value actually took over control of the target, independent of the
// exact arithmetic (which varies with the kernel's synthetic call sequence).
#[test]
fn fmod_ret_replaces_target_return_value() {
    // fmod_ret (BPF_MODIFY_RETURN) and bpf_modify_return_test both landed in 5.5.
    // https://github.com/torvalds/linux/blob/v5.5/net/bpf/test_run.c#L98-L112
    let kernel_version = KernelVersion::current().unwrap();
    if kernel_version < KernelVersion::new(5, 5, 0) {
        eprintln!("skipping test on kernel {kernel_version:?} - fmod_ret requires 5.5");
        return;
    }

    if !is_program_supported(ProgramType::Tracing).unwrap() {
        eprintln!("skipping test - tracing programs not supported");
        return;
    }

    let btf = match Btf::from_sys_fs() {
        Ok(btf) => btf,
        Err(err) => {
            eprintln!("skipping test - kernel BTF not available: {err}");
            return;
        }
    };

    // Load, attach, and test-run a single fmod_ret program, returning the
    // observed side-effect count. Each call uses its own `Ebpf` instance so the
    // program is detached (on drop) before the next one attaches to the same
    // target - otherwise both would fire during either test run.
    let run = |program: &str| -> Option<u32> {
        let mut bpf = Ebpf::load(crate::FMOD_RET).unwrap();
        let prog: &mut FModRet = bpf.program_mut(program).unwrap().try_into().unwrap();
        match prog.load(MODIFY_RETURN_TARGET, &btf) {
            Ok(()) => {}
            Err(ProgramError::Btf(BtfError::UnknownBtfTypeName { type_name }))
                if type_name == MODIFY_RETURN_TARGET =>
            {
                return None;
            }
            Err(err) => panic!("unexpected error loading {program}: {err}"),
        }
        prog.attach().unwrap();
        Some(side_effect_count(prog.test_run(()).unwrap()))
    };

    let Some(allow) = run("test_fmod_ret_allow") else {
        eprintln!("skipping test - {MODIFY_RETURN_TARGET} missing from kernel BTF");
        return;
    };
    let overridden = run("test_fmod_ret_override").unwrap();

    assert_eq!(
        allow,
        overridden + 1,
        "returning non-zero from fmod_ret should suppress exactly one \
         target side effect (allow={allow}, override={overridden})",
    );
}
