use core::str::FromStr;

use honggfuzz::fuzz;
use miniscript::descriptor::{ShInner, Wsh, WshInner};
use miniscript::iter::TreeLike;
use miniscript::{Descriptor, Miniscript, ScriptContext, Terminal};
use old_miniscript::Descriptor as OldDescriptor;

type Desc = Descriptor<descriptor_fuzz::FuzzPk>;
type OldDesc = OldDescriptor<descriptor_fuzz::FuzzPk>;

fn contains_sapio_nodes(descriptor: &Desc) -> bool {
    fn script<Ctx: ScriptContext>(ms: &Miniscript<descriptor_fuzz::FuzzPk, Ctx>) -> bool {
        ms.pre_order_iter().any(|node| {
            matches!(
                node.node,
                Terminal::TxTemplate(_) | Terminal::InscribePre(..) | Terminal::InscribePost(..)
            )
        })
    }
    fn wsh(descriptor: &Wsh<descriptor_fuzz::FuzzPk>) -> bool {
        match descriptor.as_inner() {
            WshInner::Ms(ms) => script(ms),
            WshInner::SortedMulti(_) => false,
        }
    }
    match descriptor {
        Descriptor::Bare(bare) => script(bare.as_inner()),
        Descriptor::Wsh(inner) => wsh(inner),
        Descriptor::Sh(sh) => match sh.as_inner() {
            ShInner::Ms(ms) => script(ms),
            ShInner::Wsh(inner) => wsh(inner),
            ShInner::Wpkh(_) | ShInner::SortedMulti(_) => false,
        },
        Descriptor::Tr(tr) => tr.leaves().any(|leaf| script(leaf.miniscript())),
        Descriptor::Pkh(_) | Descriptor::Wpkh(_) => false,
    }
}

fn do_test(data: &[u8]) {
    let data_str = String::from_utf8_lossy(data);
    match (Desc::from_str(&data_str), OldDesc::from_str(&data_str)) {
        (Err(_), Err(_)) => {}
        // Keep differential checking strict for the shared language only.
        (Ok(x), Err(_)) if contains_sapio_nodes(&x) => {}
        (Ok(x), Err(e)) => panic!("new logic parses {} as {:?}, old fails with {}", data_str, x, e),
        (Err(e), Ok(x)) => panic!("old logic parses {} as {:?}, new fails with {}", data_str, x, e),
        (Ok(new), Ok(old)) => {
            use miniscript::policy::Liftable as _;
            use old_miniscript::policy::Liftable as _;

            assert_eq!(
                old.to_string(),
                new.to_string(),
                "input {} (left is old, right is new)",
                data_str
            );

            match (new.lift(), old.lift()) {
                (Err(_), Err(_)) => {}
                (Ok(x), Err(e)) => {
                    panic!("new logic lifts {} as {:?}, old fails with {}", data_str, x, e)
                }
                (Err(e), Ok(x)) => {
                    panic!("old logic lifts {} as {:?}, new fails with {}", data_str, x, e)
                }
                (Ok(new), Ok(old)) => {
                    assert_eq!(
                        old.to_string(),
                        new.to_string(),
                        "lifted input {} (left is old, right is new)",
                        data_str
                    )
                }
            }
        }
    }
}

fn main() {
    loop {
        fuzz!(|data| {
            do_test(data);
        });
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn duplicate_crash() { crate::do_test(b"tr(d,{0,{0,0}})") }

    #[test]
    fn only_sapio_ast_nodes_are_exempt_from_old_parser_comparison() {
        use core::str::FromStr;
        for text in [
            "wsh(and_v(txtmpl(0000000000000000000000000000000000000000000000000000000000000000),pk(01)))",
            "sh(wsh(inscribe_pre(0063036f726468,pk(01))))",
            "tr(01,inscribe_post(0063036f726468,pk(03)))",
        ] {
            let descriptor = super::Desc::from_str(text).unwrap();
            assert!(super::contains_sapio_nodes(&descriptor));
            assert!(super::OldDesc::from_str(text).is_err());
            crate::do_test(text.as_bytes());
        }
        let text = "wsh(pk(01))";
        assert!(!super::contains_sapio_nodes(&super::Desc::from_str(text).unwrap()));
        crate::do_test(text.as_bytes());
    }
}
