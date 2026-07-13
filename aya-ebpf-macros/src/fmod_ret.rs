use std::borrow::Cow;

use proc_macro2::TokenStream;
use quote::quote;
use syn::{ItemFn, Result};

use crate::args::Args;

pub(crate) struct FModRet {
    item: ItemFn,
    function: Option<String>,
    sleepable: bool,
}

impl FModRet {
    pub(crate) fn parse(attrs: TokenStream, item: TokenStream) -> Result<Self> {
        let item = syn::parse2(item)?;
        let mut args: Args = syn::parse2(attrs)?;
        let function = args.pop_string("function");
        let sleepable = args.pop_bool("sleepable");
        args.into_error()?;
        Ok(Self {
            item,
            function,
            sleepable,
        })
    }

    pub(crate) fn expand(&self) -> TokenStream {
        let Self {
            item,
            function,
            sleepable,
        } = self;
        let ItemFn {
            attrs: _,
            vis,
            sig,
            block: _,
        } = item;
        let section_prefix = if *sleepable { "fmod_ret.s" } else { "fmod_ret" };
        let section_name: Cow<'_, _> = if let Some(function) = function {
            format!("{section_prefix}/{function}").into()
        } else {
            section_prefix.into()
        };
        let fn_name = &sig.ident;
        // Unlike fentry/fexit, an fmod_ret program's return value REPLACES the
        // target function's return value, so it must be propagated (0 = allow,
        // negative errno = deny).
        quote! {
            #[unsafe(no_mangle)]
            #[unsafe(link_section = #section_name)]
            #vis fn #fn_name(ctx: *mut ::core::ffi::c_void) -> i32 {
                return #fn_name(::aya_ebpf::programs::FEntryContext::new(ctx));

                #item
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use syn::parse_quote;

    use super::*;

    #[test]
    fn test_fmod_ret() {
        let prog = FModRet::parse(
            parse_quote! {
                function = "should_failslab"
            },
            parse_quote! {
                fn should_failslab(ctx: &mut aya_ebpf::programs::FEntryContext) -> i32 {
                    0
                }
            },
        )
        .unwrap();
        let expanded = prog.expand();
        let expected = quote! {
            #[unsafe(no_mangle)]
            #[unsafe(link_section = "fmod_ret/should_failslab")]
            fn should_failslab(ctx: *mut ::core::ffi::c_void) -> i32 {
                return should_failslab(::aya_ebpf::programs::FEntryContext::new(ctx));

                fn should_failslab(ctx: &mut aya_ebpf::programs::FEntryContext) -> i32 {
                    0
                }
            }
        };
        assert_eq!(expected.to_string(), expanded.to_string());
    }
}
