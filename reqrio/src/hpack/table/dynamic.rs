use std::slice::Iter;
use crate::hpack::HPackItem;

pub struct DynamicTable {
    values: Vec<HPackItem>,
    max_size: usize,
    size: usize,
}

impl Default for DynamicTable {
    fn default() -> Self {
        DynamicTable {
            values: vec![],
            max_size: 4096,
            size: 0,
        }
    }
}

impl DynamicTable {
    pub fn new_size(max_size: usize) -> Self {
        DynamicTable {
            values: vec![],
            max_size,
            size: 0,
        }
    }
    pub fn size(&self) -> usize { self.size }

    pub fn max_size(&self) -> usize { self.max_size }
    ///动态表插入时应位于最前端
    ///
    /// 文档文档rfc7541-4.4
    pub fn insert(&mut self, item: HPackItem) {
        self.size += item.item_size();
        println!("{}", self.size);
        self.values.insert(0, item);
        self.resize();
    }

    /// 动态表的索引应该减去静态表的长度
    ///
    /// 文档文档rfc7541-2.3.3
    pub fn get(&self, index: usize) -> Option<&HPackItem> {
        let index = index - 61;
        self.values.get(index)
    }

    ///动态表的item遵循先入先出
    ///
    /// 文档文档rfc7541-4.3
    fn resize(&mut self) {
        while self.size > self.max_size {
            match self.values.pop() {
                None => self.size = 0,
                Some(item) => self.size -= item.item_size(),
            }
        }
    }

    pub fn iter(&self) -> Iter<'_, HPackItem> {
        self.values.iter()
    }
}