//! `Fmod_ret` programs.

use aya_obj::{
    btf::{Btf, BtfKind},
    generated::{bpf_attach_type::BPF_MODIFY_RETURN, bpf_prog_type::BPF_PROG_TYPE_TRACING},
};

use crate::programs::{
    FdLink, FdLinkId, ProgramData, ProgramError, ProgramType, define_link_wrapper,
    load_program_with_attach_type, utils::attach_raw_tracepoint,
};

/// A program that can modify the return value of kernel functions.
///
/// [`FModRet`] programs are tracing programs (like [`FEntry`](crate::programs::FEntry)
/// and [`FExit`](crate::programs::FExit)) that attach to functions registered
/// for return modification — functions marked `ALLOW_ERROR_INJECTION`. The value
/// they return replaces the target function's return value, so they can be used
/// to override its result (e.g. return `-ENOMEM` from `should_failslab` to
/// inject an allocation failure).
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 5.5.
///
/// # Examples
///
/// ```no_run
/// # #[derive(thiserror::Error, Debug)]
/// # enum Error {
/// #     #[error(transparent)]
/// #     BtfError(#[from] aya::BtfError),
/// #     #[error(transparent)]
/// #     Program(#[from] aya::programs::ProgramError),
/// #     #[error(transparent)]
/// #     Ebpf(#[from] aya::EbpfError),
/// # }
/// # let mut bpf = Ebpf::load_file("ebpf_programs.o")?;
/// use aya::{Ebpf, programs::FModRet, BtfError, Btf};
///
/// let btf = Btf::from_sys_fs()?;
/// let program: &mut FModRet = bpf.program_mut("should_failslab").unwrap().try_into()?;
/// program.load("should_failslab", &btf)?;
/// program.attach()?;
/// # Ok::<(), Error>(())
/// ```
#[derive(Debug)]
#[doc(alias = "BPF_MODIFY_RETURN")]
#[doc(alias = "BPF_PROG_TYPE_TRACING")]
pub struct FModRet {
    pub(crate) data: ProgramData<FModRetLink>,
}

impl FModRet {
    /// The type of the program according to the kernel.
    pub const PROGRAM_TYPE: ProgramType = ProgramType::Tracing;

    /// Loads the program inside the kernel.
    ///
    /// Loads the program so it modifies the return value of the kernel function
    /// `fn_name`. The `btf` argument must contain the BTF info for the running
    /// kernel.
    pub fn load(&mut self, fn_name: &str, btf: &Btf) -> Result<(), ProgramError> {
        let Self { data } = self;
        data.attach_btf_id = Some(btf.id_by_type_name_kind(fn_name, BtfKind::Func)?);
        load_program_with_attach_type(BPF_PROG_TYPE_TRACING, BPF_MODIFY_RETURN, data)
    }

    /// Attaches the program.
    ///
    /// The returned value can be used to detach, see [`FModRet::detach`].
    pub fn attach(&mut self) -> Result<FModRetLinkId, ProgramError> {
        attach_raw_tracepoint(&mut self.data, None)
    }
}

define_link_wrapper!(FModRetLink, FModRetLinkId, FdLink, FdLinkId, FModRet);
