fn main() {
    // 实验：把主线程栈从默认 1MB 提到 16MB（稍后视结果决定是否保留）。
    println!("cargo:rustc-link-arg=/STACK:16777216");
    tauri_build::build()
}
