use std::ops::Range;

pub(crate) trait CharIndexable<'b> {
    fn char_index(&'b self, range: Range<usize>) -> &'b str;
}

pub struct CharIndexableStr<'a> {
    s: &'a str,
    indices: Vec<usize>,
}

impl CharIndexableStr<'_> {
    pub(crate) fn char_count(&self) -> usize {
        self.indices.len()
    }
}

impl<'a> From<&'a str> for CharIndexableStr<'a> {
    fn from(s: &'a str) -> Self {
        CharIndexableStr {
            indices: s.char_indices().map(|(i, _c)| i).collect(),
            s,
        }
    }
}

impl<'a, 'b: 'a> CharIndexable<'b> for CharIndexableStr<'a> {
    fn char_index(&'b self, range: Range<usize>) -> &'b str {
        if range.end >= self.indices.len() {
            &self.s[self.indices[range.start]..]
        } else {
            &self.s[self.indices[range.start]..self.indices[range.end]]
        }
    }
}
