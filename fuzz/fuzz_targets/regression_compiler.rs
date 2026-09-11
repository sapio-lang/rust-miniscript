use descriptor_fuzz::FuzzPk;
use honggfuzz::fuzz;
use miniscript::iter::TreeLike;
use miniscript::{policy, ParseError, ParseNumError};
use old_miniscript::policy as old_policy;

type Policy = policy::Concrete<FuzzPk>;
type OldPolicy = old_policy::Concrete<FuzzPk>;

fn do_test(data: &[u8]) {
    let data_str = String::from_utf8_lossy(data);
    match (data_str.parse::<Policy>(), data_str.parse::<OldPolicy>()) {
        (Err(_), Err(_)) => {}
        // Upstream 12.x has no meaning for Sapio's extension nodes.
        (Ok(x), Err(_))
            if x.pre_order_iter()
                .any(|node| matches!(node, Policy::TxTemplate(_) | Policy::Inscribe(..))) => {}
        (Ok(x), Err(e)) => panic!("new logic parses {} as {:?}, old fails with {}", data_str, x, e),
        // These is anew parse error
        (
            Err(miniscript::Error::Parse(ParseError::Num(ParseNumError::IllegalZero { .. }))),
            Ok(_),
        ) => {}
        (Err(e), Ok(x)) => {
            panic!("old logic parses {} as {:?}, new fails with {:?}", data_str, x, e)
        }
        (Ok(new), Ok(old)) => {
            assert_eq!(
                old.to_string(),
                new.to_string(),
                "input {} (left is old, right is new)",
                data_str
            );

            let comp = new.compile::<miniscript::Legacy>();
            let old_comp = old.compile::<old_miniscript::Legacy>();

            match (comp, old_comp) {
                (Err(_), Err(_)) => {}
                (Ok(x), Err(e)) => {
                    panic!("new logic compiles {} as {:?}, old fails with {}", data_str, x, e)
                }
                (Err(e), Ok(x)) => {
                    panic!("old logic compiles {} as {:?}, new fails with {}", data_str, x, e)
                }
                (Ok(new), Ok(old)) => {
                    assert_eq!(
                        old.to_string(),
                        new.to_string(),
                        "input {} (left is old, right is new)",
                        data_str
                    );
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
    fn duplicate_crash() { crate::do_test(b"or(0@pk(09),0@TRIVIAL)") }

    #[test]
    fn sapio_nodes_have_no_upstream_counterpart() {
        for text in [
            "and(txtmpl(0000000000000000000000000000000000000000000000000000000000000000),pk(01))",
            "and(pk(01),inscribe(0063036f726468,pk(03)))",
        ] {
            assert!(text.parse::<super::Policy>().is_ok());
            assert!(text.parse::<super::OldPolicy>().is_err());
            crate::do_test(text.as_bytes());
        }
        crate::do_test(b"and(pk(01),older(1))");
    }
}
