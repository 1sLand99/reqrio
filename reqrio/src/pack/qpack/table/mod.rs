mod r#static;
mod dynamic;

use r#static::STATIC_TABLE;
use crate::pack::PackItem;

pub struct Table {
    static_table: &'static [PackItem; 99],
}