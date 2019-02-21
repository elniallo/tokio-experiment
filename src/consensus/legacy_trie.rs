pub struct LegacyTrie {}

impl LegacyTrie {
    pub fn get_accounts(&self, account: &[u8], root: &u8) {}
}
enum NodeType<DataType, KeyType> {
    StateNode(KeyType),
    DataNode(DataType),
}
