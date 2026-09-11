extern crate miniscript;

use bitcoind::client::bitcoin;

pub mod test_util;

// Launch the explicit override, feature-selected download, or PATH binary.
pub fn setup() -> bitcoind::BitcoinD {
    let exe_path = bitcoind::exe_path().unwrap();
    let bitcoind = bitcoind::BitcoinD::new(exe_path).unwrap();
    let cl = &bitcoind.client;
    // generate to an address by the wallet. And wait for funds to mature
    let addr = cl.new_address().unwrap();
    let blks = cl.generate_to_address(101, &addr).unwrap();
    assert_eq!(blks.0.len(), 101);

    let balance = cl
        .get_balance()
        .expect("failed to get balance")
        .balance()
        .unwrap();
    assert_eq!(balance, bitcoin::Amount::from_sat(100_000_000 * 50));
    bitcoind
}
