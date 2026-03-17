use std::slice::Iter;
use super::item::HPackItem;
use dynamic::DynamicTable;
use r#static::STATIC_TABLE;
use crate::hpack::index::Index;

mod r#static;
mod dynamic;

pub struct Table {
    static_table: &'static [HPackItem],
    dynamic_table: DynamicTable,
}

impl Default for Table {
    fn default() -> Self {
        Table {
            static_table: STATIC_TABLE.as_ref(),
            dynamic_table: DynamicTable::default(),
        }
    }
}

impl Table {
    pub fn new(max_table_size:usize) -> Self {
        Table{
            static_table:STATIC_TABLE.as_ref(),
            dynamic_table:DynamicTable::new_size(max_table_size),
        }
    }
    pub fn get(&self, index: usize) -> Option<&HPackItem> {
        match index {
            ..61 => self.static_table.get(index),
            _ => self.dynamic_table.get(index),
        }
    }

    pub fn insert(&mut self, item: HPackItem) {
        self.dynamic_table.insert(item);
    }

    pub fn iter(&self) -> TableIterator<'_> {
        TableIterator {
            static_inner: self.static_table.iter(),
            dynamic_inner: self.dynamic_table.iter(),
        }
    }

    pub fn get_by_name_value(&self, name: &str, value: &str) -> Option<Index> {
        self.iter().enumerate().find_map(|(index, item)| if item.name == name && item.value == value {
            Some(Index::Indexed(index + 1))
        } else { None })
    }

    pub fn get_by_name(&self, name: &str) -> Option<Index> {
        self.iter().enumerate().find_map(|(index, item)| if item.name == name {
            Some(Index::NameIndexedAdd(index + 1))
        } else { None })
    }
}

pub struct TableIterator<'a> {
    static_inner: Iter<'a, HPackItem>,
    dynamic_inner: Iter<'a, HPackItem>,
}

impl<'a> Iterator for TableIterator<'a> {
    type Item = &'a HPackItem;
    fn next(&mut self) -> Option<Self::Item> {
        match self.static_inner.next() {
            None => self.dynamic_inner.next(),
            Some(item) => Some(item),
        }
    }
}


#[cfg(test)]
mod tests {
    use crate::hpack::table::Table;

    #[test]
    fn test_hpack_table() {
        let mut table = Table::default();
        let item = table.get(44).unwrap();
        assert_eq!(item.name, "link");
        let mut item = table.get(57).unwrap().clone();
        assert_eq!(item.name, "user-agent");
        item.set_value("test value");
        table.insert(item);
        let mut item = table.get(53).unwrap().clone();
        assert_eq!(item.name, "server");
        item.set_value("test server");
        table.insert(item);
        let item = table.get(62).unwrap();
        assert_eq!(item.value, "test value");
        let item = table.get(61).unwrap();
        assert_eq!(item.value, "test server");
        assert_eq!(table.dynamic_table.size(), 101)
    }
}