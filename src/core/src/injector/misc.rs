use crate::injector::PAGE_SIZE;

pub fn floor_to_page_size(addr: usize) -> usize {
    addr & !(*PAGE_SIZE - 1)
}

pub fn ceil_to_page_size(addr: usize) -> usize {
    let page_size = *PAGE_SIZE;
    addr.div_ceil(page_size) * page_size
}
