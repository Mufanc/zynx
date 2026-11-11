use crate::injector::PAGE_SIZE;
use ptrace_kit::RemoteAddress;

pub fn floor_to_page_size(addr: RemoteAddress) -> RemoteAddress {
    addr & !(*PAGE_SIZE - 1)
}

pub fn ceil_to_page_size(addr: RemoteAddress) -> RemoteAddress {
    let page_size = *PAGE_SIZE;
    addr.div_ceil(page_size) * page_size
}
