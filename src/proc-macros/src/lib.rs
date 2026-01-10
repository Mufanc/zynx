use proc_macro::TokenStream;
use quote::quote;
use syn::{LitStr, parse_macro_input};

#[proc_macro]
pub fn inline_bytes(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as LitStr);

    let str = input.value();
    let bytes = str.as_bytes();
    let len = bytes.len() + 1;

    let assigns = bytes
        .iter()
        .enumerate()
        .map(|(i, byte)| quote! {str[#i] = #byte;});

    TokenStream::from(quote! {
        {
            let mut str = [0u8; #len];
            #(#assigns)*
            str
        }
    })
}
