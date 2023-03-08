pub fn format_vec_pointer(v: &Vec<u64>) -> String {
    let repr: Vec<String> = v.iter().map(|p| format!("{:?}", *p as *const u8)).collect();
    repr.join(", ")
}
