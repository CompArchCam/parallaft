# Parallaft

Parallaft detects CPU faults during program execution at low performance and energy overhead on heterogeneous processors.

## Hardware support

| Architecture | Processor                                         | Supported? | Tested? | Notes                                         |
| ------------ | ------------------------------------------------- | ---------- | ------- | --------------------------------------------- |
| aarch64      | Apple M2 (non-Pro/Max/Ultra)                      | Y          | Y       |                                               |
| aarch64      | Other pre-M4 Apple Silicon                        | Y          | N       |                                               |
| aarch64      | Arm Neoverse N1                                   | Y          | Y       |                                               |
| aarch64      | Arm Neoverse V2                                   | Y          | Y       |                                               |
| aarch64      | Arm Cortex A76 with ARMv8-PMUv3                   | Y          | Y       |                                               |
| x86_64       | Intel Core i7-12700                               | Y          | Y       | Known issues with `rep`-prefixed instructions |
| x86_64       | Intel Core i7-14700                               | Y          | Y       | Ditto                                         |
| x86_64       | Other Intel Alder Lake and Raptor Lake processors | Y          | N       |                                               |

## Prerequisites

* Linux kernel 6.7 or newer.
* [Cargo with Rust compiler](https://www.rust-lang.org/learn/get-started) 1.83.0+.

## Building

```sh
$ git clone https://github.com/CompArchCam/parallaft
$ cd parallaft
$ cargo build -r --bin parallaft
```

## Trying it out

```
$ ./target/release/parallaft --config parallaft/configs/intel_12700_fixed_interval.yml -- ls
```

## Resources
* [reproduce-parallaft-paper](https://github.com/CompArchCam/reproduce-parallaft-paper)
* Boyue Zhang, Sam Ainsworth, Lev Mukhanov, and Timothy M. Jones. 2025. Parallaft: Runtime-Based CPU Fault Tolerance via Heterogeneous Parallelism. In Proceedings of the 23rd ACM/IEEE International Symposium on Code Generation and Optimization (CGO '25). Association for Computing Machinery, New York, NY, USA, 584–599. https://doi.org/10.1145/3696443.3708946
