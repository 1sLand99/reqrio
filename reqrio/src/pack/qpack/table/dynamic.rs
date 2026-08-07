use crate::pack::PackItem;
use std::collections::{HashMap, VecDeque};

pub struct DynamicTable {
    index: usize,
    values: VecDeque<(usize, PackItem)>,
    max_size: usize,
    size: usize,
    ///Decoder 已经收到并处理到第x个动态表插入。
    increment: usize,
    ///我已经完成某个 Header Block的解码
    sec_reqs: HashMap<u64, Vec<usize>>,
}

impl DynamicTable {
    pub fn new(max_size: usize) -> Self {
        DynamicTable {
            index: 0,
            values: VecDeque::with_capacity(max_size),
            max_size,
            size: 0,
            increment: 0,
            sec_reqs: Default::default(),
        }
    }

    pub fn insert(&mut self, item: PackItem) -> bool {
        let pass = self.resize(item.item_size());
        if !pass { return pass; }
        self.size += item.item_size();
        self.values.push_back((self.index, item));
        self.index += 1;
        true
    }

    fn resize(&mut self, item_size: usize) -> bool {
        debug_assert!(item_size < self.max_size);
        if self.size + item_size <= self.max_size { return true; }
        let mut pos = 0;
        while pos < self.values.len() {
            let Some((index, _)) = self.values.get(pos)else { break; };
            if self.increment <= *index { break; }
            let ref_index = self.sec_reqs.iter().any(|(_, value)| value.iter().any(|x| x == index));
            //查到有被引用的，后面的item不再检查
            if ref_index { break; }
            let Some((_, item)) = self.values.remove(pos)else {
                pos += 1;
                continue;
            };
            self.size -= item.item_size();
        }
        self.size + item_size <= self.max_size
    }

    pub fn index(&mut self, index: usize, sid: u64, refer: bool) -> Option<&PackItem> {
        let item = self.values.iter().find(|(i, _)| i == &index);
        if item.is_some() && refer {
            self.sec_reqs.entry(sid).or_default().push(index);
        }
        item.map(|(_, item)| item)
    }

    pub fn section_ack(&mut self, sid: u64) {
        self.sec_reqs.remove(&sid);
    }
}

#[cfg(test)]
mod tests {
    use crate::pack::PackItem;
    use crate::pack::qpack::table::dynamic::DynamicTable;

    #[test]
    fn test_dynamic_table() {
        let mut table = DynamicTable::new(4096);
        table.insert(PackItem::new(":authority", "www.example.com"));
        assert_eq!(table.size, 57);
        assert_eq!(table.index, 1);
        let item = table.index(0, 0, true);
        assert!(item.is_some());
        println!("{:?}", table.sec_reqs);
    }
}