mod dynamic;
mod iter;
mod r#static;

pub use iter::TableIter;
use dynamic::DynamicTable;
use r#static::{StaticTable, STATIC_TABLE};

/// A table representing a single index address space for headers where the 
/// static and the dynamic table are combined.
#[derive(Debug)]
pub struct Table<'a> {
    /// THe static table with predefined headers.
    static_table: StaticTable<'a>,

    /// The dynamic table holding custom headers.
    dynamic_table: DynamicTable,
}

#[allow(unused)]
impl<'a> Table<'a> {
    /// Returns a new header table instance with the provided maximum allowed
    /// size of the dynamic table.
    pub fn with_dynamic_size(max_dynamic_size: u32) -> Self {
        Self {
            static_table: STATIC_TABLE,
            dynamic_table: DynamicTable::with_size(max_dynamic_size),
        }
    }

    /// Returns the total number of headers. The result includes the sum of all
    /// entries of the static and the dynamic table combined.
    pub fn len(&self) -> usize {
        self.static_table.len() + self.dynamic_table.len()
    }

    /// Returns the total number of entries stored in the dynamic table.
    pub fn dynamic_len(&self) -> usize {
        self.dynamic_table.len()
    }

    /// Returns the total size (in octets) of all the entries stored in the
    /// dynamic table.
    pub fn dynamic_size(&self) -> u32 {
        self.dynamic_table.size()
    }

    /// Returns the maximum allowed size of the dynamic table.
    pub fn max_dynamic_size(&self) -> u32 {
        self.dynamic_table.max_size()
    }
    
    /// Updates the maximum allowed size of the dynamic table.
    pub fn update_max_dynamic_size(&mut self, size: u32) {
        self.dynamic_table.update_max_size(size);
    }

    /// Returns an iterator through all the headers.
    /// 
    /// It includes entries stored in the static and the dynamic table. Since
    /// the index `0` is an invalid index, the first returned item is at index
    /// `1`. The entries returned have indices ordered sequentially in the
    /// single address space (first the headers in the static table, followed by
    /// headers in the dynamic table).
    pub fn iter(&'a self) -> TableIter<'a> {
        TableIter{ index: 1, table: self }
    }

    /// Finds a header by its index.
    /// 
    /// According to the HPACK specification, the index `0` must be treated as
    /// an invalid index number. The value for index `0` in the static table is
    /// thus missing. The index of `0` will always return `None`.
    pub fn get(&self, index: u32) -> Option<(&[u8], &[u8])> {
        let index = if index == 0 {
            return None;
        } else {
            index - 1
        };

        let static_len = self.static_table.len() as u32;
        if index < static_len {
            Some(self.static_table[index as usize])
        } else {
            self.dynamic_table.get(index - static_len)
        }
    }

    /// Searches the static and the dynamic tables for the provided header.
    /// 
    /// It tries to match both the header name and value to one of the headers
    /// in the table. If no such header exists, then it falls back to the one
    /// that matched only the name. The returned match contains the index of the
    /// header in the table and a boolean indicating whether the value of the
    /// header also matched.
    pub fn find(&self, name: &[u8], value: &[u8]) -> Option<(usize, bool)> {
        let mut name_match = None;

        for (i, h) in self.iter().enumerate() {
            if name == h.0 {
                if value == h.1 {
                    return Some((i + 1, true)); // name and value matched
                } else if name_match.is_none() {
                    name_match = Some(i + 1); // only name mached
                }
            }
        }
        name_match.map(|i|(i,false))
    }

    /// Inserts a new header at the beginning of the dynamic table.
    pub fn insert(&mut self, name: Vec<u8>, value: Vec<u8>) {
        self.dynamic_table.insert(name, value);
    }
}

impl<'a> Default for Table<'a> {
    fn default() -> Self {
        Self {
            static_table: STATIC_TABLE,
            dynamic_table: DynamicTable::default(),
        }
    }
}