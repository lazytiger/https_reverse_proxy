use std::path::PathBuf;

pub(crate) fn get_path_and_name(key: &str, prefix_len: usize) -> (PathBuf, PathBuf) {
    let data = md5::compute(key);
    let name = format!("{:x}", data);
    let dir = &name[0..prefix_len];
    let file = &name[prefix_len..];
    (dir.into(), file.into())
}
