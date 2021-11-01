// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: GPL-2.0-only

//! All the derive macros defined in this crate are for traits internal to
//! the `chrony-candm` crate. There is no need for any other crate to depend
//! directly on this one.

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, parse_quote, DeriveInput};

#[doc(hidden)]
#[proc_macro_derive(ChronySerialize, attributes(pad))]
pub fn derive_chrony_serialize(item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as DeriveInput);
    let name = input.ident;

    match input.data {
        syn::Data::Struct(ds) => derive_chrony_serialize_struct(name, ds),
        syn::Data::Enum(ds) => derive_chrony_serialize_enum(name, input.attrs.as_slice(), ds),
        _ => panic!("Cannot derive ChronySerialize for a non-struct"),
    }
}

fn derive_chrony_serialize_struct(name: proc_macro2::Ident, ds: syn::DataStruct) -> TokenStream {
    let mut length = quote!(0usize);
    let mut serialize = quote!();
    let mut deserialize = quote!();

    for field in ds.fields.iter() {
        let ty = &field.ty;
        let ident = field
            .ident
            .as_ref()
            .expect("Deriving ChronySerialize for tuple structs is not supported.");
        let pad = parse_pad_attr(field.attrs.as_ref());
        length
            .extend(quote! { + <#ty as ::chrony_candm::common::ChronySerialize>::length() + #pad });
        serialize.extend(quote! {
            ::chrony_candm::common::ChronySerialize::serialize(&self.#ident, buf);
            if #pad != 0 {
                buf.put_bytes(0, #pad)
            }
        });
        deserialize.extend(quote! {
            #ident: {
                let field = <#ty as ::chrony_candm::common::ChronySerialize>::deserialize_unchecked(buf)?;
                if #pad != 0 {
                    buf.advance(#pad)
                }
                field
            },
        })
    }

    let expanded = quote! {
        impl ::chrony_candm::common::ChronySerialize for #name {
            fn length() -> usize {
                #length
            }

            fn serialize<B: ::bytes::BufMut>(&self, buf: &mut B) {
                #serialize
            }

            fn deserialize_unchecked<B: ::bytes::Buf>(buf: &mut B) -> ::std::result::Result<Self, ::chrony_candm::common::DeserializationError> {
                ::std::result::Result::Ok(#name {
                    #deserialize
                })
            }

        }
    };

    TokenStream::from(expanded)
}

fn derive_chrony_serialize_enum(
    name: proc_macro2::Ident,
    attrs: &[syn::Attribute],
    _ds: syn::DataEnum,
) -> TokenStream {
    let repr = attrs
        .iter()
        .find_map(|attr| {
            if let syn::Meta::List(meta_list) = attr.parse_meta().ok()? {
                if meta_list.path.get_ident()? == "repr" {
                    let repr = meta_list.nested.iter().next()?;
                    let repr: syn::Ident = parse_quote! { #repr };
                    Some(repr)
                } else {
                    None
                }
            } else {
                None
            }
        })
        .expect("Must specify a #[repr] attribute to derive ChronySerialize for an enum.");

    let expanded = quote! {
        impl ::chrony_candm::common::ChronySerialize for #name {
            fn length() -> usize {
                ::std::mem::size_of::<#repr>()
            }

            fn serialize<B: ::bytes::BufMut>(&self, buf: &mut B) {
                buf.put_slice((&<#repr>::from(*self).to_be_bytes()) as &[u8]);
            }

            fn deserialize_unchecked<B: ::bytes::Buf>(buf: &mut B) -> ::std::result::Result<Self, ::chrony_candm::common::DeserializationError> {
                let mut dst = [0u8; ::std::mem::size_of::<#repr>()];
                buf.copy_to_slice(&mut dst);
                <Self as ::std::convert::TryFrom<#repr>>::try_from(<#repr>::from_be_bytes(dst)).map_err(|_| ::chrony_candm::common::DeserializationError::new("value outside of enum range"))
            }
        }
    };

    TokenStream::from(expanded)
}

#[doc(hidden)]
#[proc_macro_derive(ChronyMessage, attributes(pad, cmd))]
pub fn derive_chrony_message(item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as DeriveInput);
    let name = input.ident;

    let ds = match input.data {
        syn::Data::Enum(ds) => ds,
        _ => panic!("Cannot derive ChronyMessage for a non-enum"),
    };

    let mut length = quote!();
    let mut cmd = quote!();
    let mut serialize = quote!();
    let mut deserialize = quote!();

    let mut index = 0u16;
    for variant in ds.variants.iter() {
        let ident = &variant.ident;
        let mut iter = variant.fields.iter();
        let arg = iter.next();
        if arg.is_some() {
            if iter.next().is_some() {
                panic!("ChronyMessage variants must have at most a single field.")
            }
        }

        let pad = parse_pad_attr(variant.attrs.as_ref());
        if let Some(cmd) = parse_cmd_attr(variant.attrs.as_ref()) {
            if index > cmd {
                panic!("Command numbers must be strictly increasing.")
            }
            index = cmd;
        }

        match arg {
            Some(field) => {
                let ty = &field.ty;
                length.extend(quote! { Self::#ident(_) => <#ty as ::chrony_candm::common::ChronySerialize>::length() + #pad, });
                cmd.extend(quote! { Self::#ident(_) => #index, });
                serialize.extend(quote! {
                    Self::#ident(x) => {
                        if #pad != 0 {
                            buf.put_bytes(0, #pad)
                        }
                        ::chrony_candm::common::ChronySerialize::serialize(x, buf);
                    },
                });
                deserialize.extend(quote! {
                    #index => {
                        if #pad != 0 {
                            buf.advance(#pad)
                        }
                        let body = <#ty as ::chrony_candm::common::ChronySerialize>::deserialize(buf)?;
                        Ok(Self::#ident(body))
                    },
                });
            }
            None => {
                length.extend(quote! { Self::#ident => #pad, });
                cmd.extend(quote! { Self::#ident => #index, });
                serialize.extend(quote! {
                    Self::#ident => {
                        if #pad != 0 {
                            buf.put_bytes(0, #pad)
                        }
                    },
                });
                deserialize.extend(quote! {
                    #index => {
                        if #pad != 0 {
                            buf.advance(#pad)
                        }
                        Ok(Self::#ident)
                    },
                });
            }
        };

        index += 1;
    }

    let expanded = quote! {
        impl ::chrony_candm::common::ChronyMessage for #name {
            fn body_length(&self) -> usize {
                match self {
                    #length
                }
            }

            fn cmd(&self) -> u16 {
                match self {
                    #cmd
                }
            }

            fn serialize_body<B: ::bytes::BufMut>(&self, buf: &mut B) {
                match self {
                    #serialize
                }
            }

            fn deserialize_body<B: ::bytes::Buf>(cmd: u16, buf: &mut B) -> ::std::result::Result<Self, ::chrony_candm::common::DeserializationError> {
                match cmd {
                    #deserialize
                    _ => ::std::result::Result::Err(::chrony_candm::common::DeserializationError::new("unsupported command number"))
                }
            }

        }
    };

    TokenStream::from(expanded)
}

fn parse_pad_attr(attrs: &[syn::Attribute]) -> usize {
    for attr in attrs.iter() {
        if let Ok(syn::Meta::NameValue(meta_namevalue)) = attr.parse_meta() {
            if meta_namevalue.path.is_ident("pad") {
                if let syn::Lit::Int(i) = meta_namevalue.lit {
                    match i.base10_parse() {
                        Ok(size) => return size,
                        Err(e) => panic!("{}", e),
                    }
                } else {
                    panic!("Argument to pad attribute must be an integer literal")
                }
            }
        }
    }

    0
}

fn parse_cmd_attr(attrs: &[syn::Attribute]) -> Option<u16> {
    for attr in attrs.iter() {
        if let Ok(syn::Meta::NameValue(meta_namevalue)) = attr.parse_meta() {
            if meta_namevalue.path.is_ident("cmd") {
                if let syn::Lit::Int(i) = meta_namevalue.lit {
                    match i.base10_parse() {
                        Ok(cmd) => return Some(cmd),
                        Err(e) => panic!("{}", e),
                    }
                } else {
                    panic!("Argument to cmd attribute must be an integer literal")
                }
            }
        }
    }

    None
}
