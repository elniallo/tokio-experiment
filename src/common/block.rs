use common::meta_info::MetaInfo;
use common::signed_tx::SignedTx;
use common::tx::{Quantifiable, Signed, Tx};
use common::header::{Rooted, Header, Mined, Raw};

pub struct Block<T, U>
    where T: Rooted + Raw + Mined,
          U: Quantifiable + Signed {
    header: T,
    txs: Option<Vec<U>>,
    meta: Option<MetaInfo>,
}

pub trait Base {
    fn get_header<T>(&self) -> T;
}

pub trait Body {
    fn get_txs<U>(&self) -> Vec<U>;
}

pub trait Meta {
    fn get_meta(&self) -> MetaInfo;
}

// impl Block<Header, SignedTx<Tx>>
//     where Header: Rooted + Raw + Mined,
//           SignedTx<Tx>: Quantifiable + Signed {
//     fn from_header(header: Header)-> Block<Header, SignedTx<Tx>> {

//     }
// }