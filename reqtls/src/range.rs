use std::ops::Range;

pub trait RangeExt<T> {
    fn add(self, n: T) -> Self;
}

impl RangeExt<usize> for Range<usize> {
    fn add(mut self, n: usize) -> Self {
        self.start += n;
        self.end += n;
        self
    }
}